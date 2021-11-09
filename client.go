package mysqlclient

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const socket = "/run/mysqld/mysqld.sock"
const packetSize = 16777215

type Session struct {
	conn net.Conn
	*payloadBuf
	Queries       uint64
	LastQuery     []byte
	LastQueryTime time.Time
	Created       time.Time
	lastReset     int64
	isDead        bool
	onGoingQuery  bool
}
type DbinfoT struct {
	dbName      []byte
	dbUser      []byte
	dbPassSha1  []byte
	loginPrefix []byte
	loginSuffix []byte //20
}

const defCaps = cLIENT_CONNECT_WITH_DB |
	cLIENT_CONNECT_WITH_DB |
	cLIENT_PLUGIN_AUTH |
	cLIENT_TRANSACTIONS |
	cLIENT_PROTOCOL_41 |
	cLIENT_DEPRECATE_EOF
	//cLIENT_OPTIONAL_RESULTSET_METADATA |
	// cLIENT_QUERY_ATTRIBUTES

func StartNewDb(dbName string, dbUser string, dbPass string) *DbinfoT {

	dbinfo := &DbinfoT{
		dbName:     []byte(dbName),
		dbUser:     []byte(dbUser),
		dbPassSha1: sha1Sum([]byte(dbPass)),
	}
	buf := new(bytes.Buffer)

	var b = make([]byte, 4)
	// cLIENT_QUERY_ATTRIBUTES
	calcBytes(defCaps, b) // flags
	buf.Write(b)
	calcBytes(0, b) // max packets
	buf.Write(b)

	buf.WriteByte(255)               // charset utf8mb4_0900_ai_ci
	buf.Write(make([]byte, 23))      // filter
	buf.WriteString(dbUser)          // username
	buf.WriteByte(0)                 //null term for dbuser
	buf.WriteByte(20)                // len of auth data
	dbinfo.loginPrefix = buf.Bytes() // save

	buf = new(bytes.Buffer)
	buf.Write(dbinfo.dbName) // add dbname to suffix
	buf.WriteByte(0)         // null terminate dbname

	buf.WriteString("mysql_native_password")
	buf.WriteByte(0)

	dbinfo.loginSuffix = buf.Bytes()

	return dbinfo
}

func (info *DbinfoT) NewSesstion() (sess *Session) {
	var conn net.Conn
	defer func() {
		if r := recover(); r != nil {
			if conn != nil {
				conn.Close()
			}
			panic(fmt.Sprint(r))
		}
	}()

	conn, err := net.Dial("unix", socket)
	if err != nil {
		panic(err)
	}
	// conn.SetDeadline(time.Now().Add(time.Second * 15))
	now := time.Now()
	sess = &Session{
		conn:          conn,
		payloadBuf:    NewPackBuf(),
		Created:       now,
		lastReset:     now.UnixMilli(),
		LastQueryTime: now,
	}
	b, _ := sess.readPayload()
	if b[0] != 10 {
		ErrOrOk(b)
		panic("protocol err? 1")
	}

	b, _ = readUntil(b, 0x00) // versions

	b, _ = readBytes(b, 4) // threadid

	// first part of challenge
	b, sChallenge := readBytes(b, 8)

	b, _ = readBytes(b, 1+2+1+2+2+1+10) // filter+cap1+charset+status_flag+cap2

	sChallenge = append(sChallenge, b[:12]...)

	// pluginName := b[12:]

	arr := sha1.Sum(append(sChallenge, sha1Sum(info.dbPassSha1)...))

	for i := range arr {
		arr[i] = arr[i] ^ info.dbPassSha1[i]
	}
	// sess.w.Write(info.loginPrefix, sChallenge, info.loginSuffix)
	sess.writeAndSend(conn, 1, info.loginPrefix, arr[:], info.loginSuffix)
	b, _ = sess.readPayload()
	if !ErrOrOk(b) {
		panic("Not OK then what?")
	}

	// do some init:
	initConn(sess)

	return sess
}

const WaitTimeoutSec = 62

var initConnCommand = "SET SESSION transaction_isolation='READ-COMMITTED', sql_mode='STRICT_ALL_TABLES', sql_safe_updates=1, sql_select_limit=10000, wait_timeout=" + strconv.Itoa(WaitTimeoutSec)

func initConn(sess *Session) {
	sess.TextCommand(initConnCommand)
}

// Insert single row in database
func (sess *Session) Insert(table string, data map[string]interface{}) (insertedId uint) {
	dataLen := len(data)
	args := make([]interface{}, dataLen)
	var w strings.Builder
	w.Grow(250)
	w.WriteString("INSERT INTO ")
	w.WriteString(table)
	w.WriteString(" SET\n")
	i := -1
	for k, v := range data {
		i++
		w.WriteString(k)
		w.WriteString("=?")
		if i < dataLen-1 {
			w.WriteString(",\n")
		}
		args = append(args, v)
	}
	ok := sess.Exec(w.String(), args...)
	return ok.Inserted
}

// update db row(s) based on condition (single where column and single whereValue)
/*
	sess.Update(
		"users",
		map[string]interface{}{
			"lastPostUnix": time.Now().Unix()
		},
		"userid",
		10,
	)
*/
func (sess *Session) Update(table string, data map[string]interface{}, whereCol string, whereValue interface{}) (updated uint) {

	dataLen := len(data)
	if dataLen == 0 {
		return 0
	}
	args := make([]interface{}, dataLen+1)
	var w strings.Builder
	w.Grow(250)
	w.WriteString("UPDATE ")
	w.WriteString(table)
	w.WriteString(" SET\n")
	i := -1
	for k, v := range data {
		i++
		w.WriteString(k)
		w.WriteString("=?")
		if i < dataLen-1 {
			w.WriteString(",\n")
		}
		args = append(args, v)
	}
	w.WriteString("\nWHERE ")
	w.WriteString(whereCol)
	w.WriteString("=?")
	args = append(args, whereValue)
	ok := sess.Exec(w.String(), args...)
	return ok.Affected
}

// Delete row(s) based on condition
func (sess *Session) Delete(table string, where string, args ...interface{}) uint {
	ok := sess.Exec("DELETE FROM "+table+" WHERE "+where, args...)
	return ok.Affected
}

// Begin transaction
func (sess *Session) Begin() {
	sess.TextCommand("Begin")
}

// Commit transaction
func (sess *Session) Commit() {
	sess.TextCommand("Commit")
}

// Rollback transaction
func (sess *Session) Rollback() {
	sess.TextCommand("ROLLBACK")
}

// Count rows based on condition
func (sess *Session) CountRows(table, string, where string, args ...interface{}) int {
	i := new(int)
	sess.GetVar(i, "Select COUNT(*) FROM "+table+" WHERE "+where, args...)
	return *i
}
func (sess *Session) GetVar(v interface{}, query string, args ...interface{}) {
	onGoing := sess.StartQuery(query, args...)
	var first bool
	onGoing.WithEachRow(func(b [][]byte) {
		if first {
			panic("more than one row")
		}
		first = true
		switch v.(type) {
		case *int:
			*v.(*int) = toInt(b[0])
		case *float64:
			*v.(*float64) = toFloat(b[0])
		case *uint64:
			*v.(*uint64) = toBigUint(b[0])
		case *uint:
			*v.(*uint) = uint(toBigUint(b[0]))
		case *string:
			*v.(*string) = toStr(b[0])
		case *[]byte:
			*v.(*[]byte) = make([]byte, len(b[0]))
			copy(*v.(*[]byte), b[0])
		default:
			panic("unkown data type")
		}
		return
	}, false)
}
func toInt(b []byte) (i int) {
	i, _ = strconv.Atoi(string(b))
	return
}
func toFloat(b []byte) (f float64) {
	f, _ = strconv.ParseFloat(string(b), 64)
	return
}
func toBigUint(b []byte) (u uint64) {
	u, _ = strconv.ParseUint(string(b), 10, 64)
	return
}
func toStr(b []byte) string {
	return string(b)
}

type DebugQuery struct {
	Query   string
	Explain Result
}

func (deb *DebugQuery) String() string {
	var explain string
	if deb.Explain.Count() == 0 {
		explain = "No Explain"
	} else {
		explain = deb.Explain.String()
	}
	return fmt.Sprintf("Query: %s\nExplain:\n%s\n", deb.Query, explain)
}

func (sess *Session) DebugLast() DebugQuery {
	lines := bytes.Split(sess.LastQuery, []byte{'\n'})
	for i := range lines {
		lines[i] = bytes.Trim(lines[i], "\n\t\r ")
	}
	query := bytes.Join(lines, []byte{'\n'})
	debug := DebugQuery{
		Query: string(query),
	}
	// select
	// update
	// insert
	// delete
	if len(query) < 6 {
		return debug
	}
	switch string(bytes.ToLower(query[:6])) {
	case "select", "update", "insert", "delete":
		debug.Explain = sess.Query("EXPLAIN " + debug.Query)
	}
	return debug
}

// get only one row, panic if more than one row
func (sess *Session) QueryOne(query string, args ...interface{}) (ok bool, row Row) {

	res := sess.Query(query, args...)
	if res.Count() > 1 {
		panic("returning more than one row for your query: " + query)
	}
	if res.Count() == 0 {
		return
	}
	return true, res.GetRow(0)
}

type ColType byte

const (
	ColTypeInt ColType = iota
	ColTypeBigUInt
	ColTypeFloat
	// str is actually byte slice of non numeric types
	ColTypeStr
	// colTypeAny
)

type Result struct {
	Cols  map[string]uint
	Data  [][][]byte // int or string
	types []ColType
}
type Row struct {
	Result Result
	i      int
}

func (res Result) Count() int {
	return len(res.Data)
}
func (res Result) GetRow(i int) Row {
	return Row{res, i}
}
func (res Result) ForEach(exec func(Row)) {
	l := len(res.Data)
	for i := 0; i < l; i++ {
		exec(Row{res, i})
	}
}
func (res Result) ColsSlice() []string {
	cols := make([]string, len(res.Cols))
	for key, value := range res.Cols {
		cols[value] = key
	}
	return cols
}
func (res Result) ToMapSlice() []map[string]interface{} {
	sl := make([]map[string]interface{}, 0, res.Count())
	res.ForEach(func(r Row) {
		sl = append(sl, r.ToMap())
	})
	return sl
}
func (res Result) String() string {
	b, err := json.MarshalIndent(res.ToMapSlice(), "", " ")
	if err != nil {
		panic(err)
	}
	return string(b)
}
func (res Result) Html() string {
	var w strings.Builder
	w.WriteString(`<table class="dbresult"><tr>`)
	for _, col := range res.ColsSlice() {
		w.WriteString(`<th>`)
		w.WriteString(html.EscapeString(string(col)))
		w.WriteString(`</th>`)
	}
	w.WriteString("</tr>")
	for _, row := range res.Data {
		w.WriteString(`<tr>`)
		for _, data := range row {
			w.WriteString(`<td>`)
			w.WriteString(html.EscapeString(string(data)))
			w.WriteString(`</td>`)
		}
		w.WriteString(`</tr>`)
	}
	w.WriteString(`</table>`)
	return w.String()
}
func (row Row) Get(col string) (uint, []byte) {
	i, ok := row.Result.Cols[col]
	if !ok {
		panic("column: " + col + "not exists")
	}
	return i, row.Result.Data[row.i][i]
}
func (row Row) Int(col string) int {
	_, val := row.Get(col)
	i, _ := strconv.Atoi(string(val))
	return i
}
func (row Row) Float(col string) float64 {
	_, val := row.Get(col)
	f, _ := strconv.ParseFloat(string(val), 64)
	return f
}
func (row Row) BigUint(col string) uint64 {
	_, val := row.Get(col)
	u, _ := strconv.ParseUint(string(val), 10, 64)
	return u
}
func (row Row) Str(col string) string {
	_, val := row.Get(col)
	return string(val)
}
func (row Row) Bytes(col string) []byte {
	_, val := row.Get(col)
	return val
}
func (row Row) ToMap() map[string]interface{} {
	m := make(map[string]interface{}, row.Result.Count())
	for key, i := range row.Result.Cols {
		// val := row.Result.Data[row.i][i]
		switch row.Result.types[i] {
		case ColTypeInt:
			m[key] = row.Int(key)
		case ColTypeBigUInt:
			m[key] = row.BigUint(key)
		case ColTypeFloat:
			m[key] = row.Float(key)
		default:
			m[key] = row.Str(key)
		}
	}
	return m
}
func (row Row) String() string {
	b, err := json.MarshalIndent(row.ToMap(), "", " ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (sess *Session) Exec(query string, args ...interface{}) OkPacket {
	b, isOk := sess.query(query, args)
	if !isOk {
		sess.conn.Close()
		panic("not Exec query, please use Query to get resultset")

	}
	return parseOk(b)
}

type ColumnInfo struct {
	Type ColType
	name []byte
}
type OnGoingQuery struct {
	*Session
	ColNum  uint
	gotCols bool
}

func (onGoing *OnGoingQuery) WithEachCol(each func(colName []byte, colType ColType)) {

	if onGoing.gotCols {
		panic("already called")
	}
	if !onGoing.onGoingQuery {
		panic("no onGoing query")
	}
	onGoing.gotCols = true
	var colName []byte
	var t byte
	var colType ColType
	var flags uint
	var b []byte
	for i := uint(0); i < onGoing.ColNum; i++ {
		b, _ = onGoing.readPayload()
		if each == nil {
			continue
		}
		b, _ = readLenEncStr(b)       // catalog
		b, _ = readLenEncStr(b)       // schema
		b, _ = readLenEncStr(b)       // table
		b, _ = readLenEncStr(b)       // org_table
		b, colName = readLenEncStr(b) // name
		b, _ = readLenEncStr(b)       // org_name
		b, _ = calcLenEncInt(b)       // length of fixed length fields
		b = b[2:]                     // b, _ = readBytes(b, 2)    // character_set
		b = b[4:]                     // b, _ = readBytes(b, 4)    // column_length
		t = b[0]                      // type
		b = b[1:]
		flags = calcInt(b[:2]) // such as unsigned or nullable
		switch t {
		case mYSQL_TYPE_LONGLONG:

			if flags&32 > 0 {
				colType = ColTypeBigUInt
			} else {
				colType = ColTypeInt
			}
		case /*int*/ mYSQL_TYPE_TINY, mYSQL_TYPE_SHORT, mYSQL_TYPE_LONG, mYSQL_TYPE_INT24, mYSQL_TYPE_YEAR, mYSQL_TYPE_BOOL:
			colType = ColTypeInt
		case /*float*/ mYSQL_TYPE_FLOAT, mYSQL_TYPE_DOUBLE, mYSQL_TYPE_DECIMAL, mYSQL_TYPE_NEWDECIMAL:
			colType = ColTypeFloat
		default:
			colType = ColTypeStr
		}
		each(colName, colType)
	}
}
func (onGoing *OnGoingQuery) WithEachRow(each func(data [][]byte), copyBuffer bool) {
	if !onGoing.gotCols {
		onGoing.WithEachCol(nil)
	}
	var data = make([][]byte, onGoing.ColNum)

	b, _ := onGoing.readPayload()
	if copyBuffer {
		bb := make([]byte, len(b))
		copy(bb, b)
		b = bb
	}
	ErrOrOk(b)
	if isEof(b) {
		onGoing.onGoingQuery = false
		onGoing.Session = nil
		return
	}
	for i := range data {
		if b[0] == 0xFB {
			b = b[1:]
			continue
		}
		b, data[i] = readLenEncStr(b)
	}
	each(data)
}
func (sess *Session) StartQuery(query string, args ...interface{}) (onGoing OnGoingQuery) {

	if sess.onGoingQuery {
		panic("You have not fetch last Query data")
	}
	b, isOk := sess.query(query, args)

	if isOk {
		return
	}
	_, onGoing.ColNum = calcLenEncInt(b)
	sess.onGoingQuery = true
	return
}

func (sess *Session) Query(query string, args ...interface{}) (res Result) {
	onGoing := sess.StartQuery(query, args...)
	res = Result{
		Cols:  make(map[string]uint, onGoing.ColNum),
		types: make([]ColType, onGoing.ColNum),
	}
	i := uint(0)
	onGoing.WithEachCol(func(colName []byte, colType ColType) {
		res.types[i] = colType
		res.Cols[string(colName)] = i
		i++
	})
	onGoing.WithEachRow(func(b [][]byte) {
		res.Data = append(res.Data, b)
	}, true)
	return
}

const queryComm byte = 0x03

func (sess *Session) query(query string, args []interface{}) ([]byte, bool) {

	sess.writeByte(queryComm)
	if len(args) == 0 {
		sess.writeString(query)
	} else {
		writeQueryWithargs(sess, query, args)
	}
	sess.Queries++
	sess.LastQuery = sess.LastQuery[:0]
	sess.LastQuery = append(sess.LastQuery, sess.b[1:]...)
	// t := time.Now()
	sess.sendPayload(0)
	b, _ := sess.readPayload()
	// sess.LastDuration = time.Now().Sub(t)
	sess.LastQueryTime = time.Now()

	return b, ErrOrOk(b)
}

func (sess *Session) TextCommand(sqlCommand string) {
	sess.writeByte(queryComm)
	sess.writeString(sqlCommand)
	sess.sendPayload(0)
	b, _ := sess.readPayload()
	sess.LastQueryTime = time.Now()
	if !ErrOrOk(b) {
		panic("not a command")
	}
}
func (sess *Session) EncodeQuery(query string, args []interface{}) string {
	writeQueryWithargs(sess, query, args)
	b := sess.b
	sess.reset()
	return string(b)
}

// Part of query that will not be escaped
type SqlString string

func writeQueryWithargs(sess *Session, query string, args []interface{}) {
	defer func() {
		if r := recover(); r != nil {
			sess.reset()
			panic(r)
		}
	}()
	ql := len(query)
	if ql == 0 {
		sess.writeString(query)
		return
	}
	for i := 0; i < ql; i++ {
		if query[i] == '?' {
			escapeargTo(sess, args[0])
			args = args[1:]
			continue
		}
		sess.writeByte(query[i])
	}
}
func escapeargTo(sess *Session, arg interface{}) {
	switch arg.(type) {
	case nil:
		sess.writeString("NULL")
	case bool:
		if arg.(bool) {
			sess.writeString("1")
		} else {
			sess.writeString("0")
		}

	case string:
		s := arg.(string)
		sess.writeByte('\'')
		for i := 0; i < len(s); i++ {
			sess.WriteEscaped(s[i])
		}
		sess.writeByte('\'')
	case SqlString:
		sess.writeString(string(arg.(SqlString)))

	case []byte:
		s := arg.([]byte)
		sess.writeByte('\'')
		for i := 0; i < len(s); i++ {
			sess.WriteEscaped(s[i])
		}
		sess.writeByte('\'')
	case int:
		sess.writeString(strconv.Itoa(arg.(int)))
	case uint:
		sess.writeString(strconv.FormatUint(uint64(arg.(uint)), 10))
	case float64:
		sess.writeString(strconv.FormatFloat(arg.(float64), 'f', -1, 64))
	case uint64:
		sess.writeString(strconv.FormatUint(arg.(uint64), 10))
	case int64:
		sess.writeString(strconv.Itoa(int(arg.(int64))))
	case []int:
		ii := arg.([]int)
		for i, v := range ii {
			sess.writeString(strconv.Itoa(v))
			if i == len(ii)-1 {
				break
			}
			sess.writeByte(',')
		}
	case []string:
		ss := arg.([]string)
		for i, v := range ss {
			sess.writeByte('\'')
			for j := 0; j < len(v); j++ {
				sess.WriteEscaped(v[j])
			}
			sess.writeByte('\'')
			if i == len(ss)-1 {
				break
			}
			sess.writeByte(',')
		}
	default:
		panic(fmt.Sprintf("Data type: %T is Unknown", arg))
	}
}

func readLenEncStr(b []byte) (newB []byte, str []byte) {
	newB, l := calcLenEncInt(b)
	newB, str = readBytes(newB, int(l))
	return
}

const pingComm byte = 0x0E

func (sess *Session) Ping() (bool, OkPacket) {
	defer func() {
		if r := recover(); r != nil {
			sess.conn.Close()
		}
	}()
	sess.writeByte(pingComm)
	sess.sendPayload(0)
	b, _ := sess.readPayload()
	sess.LastQueryTime = time.Now()
	ErrOrOk(b)
	ok := parseOk(b)
	return true, ok
}

const resetComm byte = 0x1F

func (sess *Session) ResetSession() bool {
	defer func() {
		if r := recover(); r != nil {
			sess.conn.Close()
		}
	}()
	sess.writeByte(resetComm)
	sess.sendPayload(0)
	b, _ := sess.readPayload()
	ErrOrOk(b)
	initConn(sess)
	sess.lastReset = time.Now().UnixMilli()
	return true
}

type OkPacket struct {
	Affected uint
	Inserted uint
	Warnning uint
	InTrans  bool
	Status   string
}

func (ok OkPacket) String() string {
	b, _ := json.MarshalIndent(ok, "", " ")
	return string(b)
}

func parseOk(packet []byte) (ok OkPacket) {
	if !ErrOrOk(packet) {
		panic("not ok or error")
	}
	packet, ok.Affected = calcLenEncInt(packet[1:])
	packet, ok.Inserted = calcLenEncInt(packet)
	if calcInt(packet[:2])&1 == 1 {
		ok.InTrans = true
	}
	ok.Warnning = calcInt(packet[2:4])
	ok.Status = string(packet[4:])
	return
}

func calcInt(b []byte) uint {
	n := uint(0)
	for i, v := range b {
		n += uint(v) << (8 * i)
	}
	return n
}
func calcBytes(u int, b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = byte(u)
		u = u >> 8
	}
}
func calcLenEncInt(b []byte) (newB []byte, i uint) {

	if b[0] < 251 {
		return b[1:], uint(b[0])
	}

	switch b[0] { // 3 bytes
	case 0xFC:
		return b[3:], calcInt(b[1:3])
	case 0xFD:
		return b[4:], calcInt(b[1:4])
	case 0xFE:
		return b[9:], calcInt(b[1:9])
	}
	panic("protocol err ? ")
}

func readBytes(b []byte, n int) (newb []byte, read []byte) {
	if len(b) < n {
		panic("not enough bytes to read")
	}
	return b[n:], b[:n]
}
func readUntil(b []byte, c byte) (newb []byte, read []byte) {
	i := bytes.IndexByte(b, c)
	if i == -1 {
		panic("did not found c")
	}
	return b[i+1:], b[:i+1]
}

// func readPayload(sess *Session) (b []byte, lastSeqId byte) {

// 	var err error
// 	header := make([]byte, 4)
// 	sess.r = sess.r[:0]
// 	for i := 0; true; i++ {
// 		if i >= 10 {
// 			panic("Server sent too many packets")
// 		}
// 		_, err = sess.conn.Read(header)
// 		if err != nil {
// 			panic(err)
// 		}
// 		l := int(calcInt(header[:3]))
// 		lastSeqId = header[3]
// 		if l == 0 {
// 			return
// 		}
// 		if l > packetSize {
// 			panic("large packet size? ")
// 		}
// 		sess.r = GrowSliceLen(sess.r, l)
// 		_, err = sess.conn.Read(sess.r[len(sess.r)-l:])
// 		if err != nil {
// 			panic(err)
// 		}
// 		if l < packetSize {
// 			break
// 		}

// 	}
// 	return sess.r, lastSeqId
// }

// func GrowSliceLen(b []byte, by int) []byte {
// 	total := len(b) + by
// 	if cap(b) < total {
// 		bb := make([]byte, total, total+100)
// 		copy(bb, b)
// 		return bb
// 	}
// 	return b[:total]
// }

// func WritePacket(conn net.Conn, seqId uint8, parts ...[]byte) {
// 	header := make([]byte, 4)
// 	var i int
// 	for _, v := range parts {
// 		i += len(v)
// 	}
// 	calcBytes(i, header[:3])
// 	header[3] = seqId
// 	_, err := conn.Write(header)
// 	if err != nil {
// 		panic(err)
// 	}
// 	for _, v := range parts {
// 		_, err = conn.Write(v)
// 	}
// 	if err != nil {
// 		panic(err)
// 	}
// }

func readConn(r io.Reader, l uint) []byte {
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		panic(err)
	}
	return b
}

func ErrOrOk(b []byte) (ok bool) {
	if b[0] == 0xff {
		// read error

		panic("Sql Error: " + string(b[3:]))
	}
	return b[0] == 0
}
func isEof(b []byte) bool {
	return b[0] == 0xfe
}
func sha1Sum(b []byte) []byte {
	arr := sha1.Sum(b)
	return arr[:]
}

const (
	cLIENT_LONG_PASSWORD uint = 1

	cLIENT_FOUND_ROWS = 2

	cLIENT_LONG_FLAG = 4

	cLIENT_CONNECT_WITH_DB = 8

	cLIENT_NO_SCHEMA = 16

	cLIENT_COMPRESS = 32

	cLIENT_ODBC = 64

	cLIENT_LOCAL_FILES = 128

	cLIENT_IGNORE_SPACE = 256

	cLIENT_PROTOCOL_41 = 512

	cLIENT_INTERACTIVE = 1024

	cLIENT_SSL = 2048

	cLIENT_IGNORE_SIGPIPE = 4096

	cLIENT_TRANSACTIONS = 8192

	cLIENT_RESERVED = 16384

	cLIENT_SECURE_CONNECTION = 32768

	cLIENT_MULTI_STATEMENTS = (1 << 16)

	cLIENT_MULTI_RESULTS = (1 << 17)

	cLIENT_PS_MULTI_RESULTS = (1 << 18)

	cLIENT_PLUGIN_AUTH = (1 << 19)

	cLIENT_CONNECT_ATTRS = (1 << 20)

	cLIENT_PLUGIN_AUTH_LENENC_cLIENT_DATA = (1 << 21)

	cLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = (1 << 22)

	cLIENT_SESSION_TRACK = (1 << 23)

	cLIENT_DEPRECATE_EOF = (1 << 24)

	cLIENT_OPTIONAL_RESULTSET_METADATA = (1 << 25)

	cLIENT_ZSTD_COMPRESSION_ALGORITHM = (1 << 26)

	cLIENT_QUERY_ATTRIBUTES = (1 << 27)

	cLIENT_CAPABILITY_EXTENSION = (1 << 29)

	cLIENT_SSL_VERIFY_SERVER_CERT = (1 << 30)

	cLIENT_REMEMBER_OPTIONS = (1 << 31)
)

//int mYSQL_TYPE_TINY, mYSQL_TYPE_SHORT, mYSQL_TYPE_LONG, mYSQL_TYPE_LONGLONG,mYSQL_TYPE_INT24,mYSQL_TYPE_YEAR
//float mYSQL_TYPE_FLOAT, mYSQL_TYPE_DOUBLE, mYSQL_TYPE_DECIMAL
// string mYSQL_TYPE_NULL,mYSQL_TYPE_TIMESTAMP,mYSQL_TYPE_DATE,mYSQL_TYPE_TIME,
const (
	mYSQL_TYPE_DECIMAL byte = iota
	mYSQL_TYPE_TINY
	mYSQL_TYPE_SHORT
	mYSQL_TYPE_LONG
	mYSQL_TYPE_FLOAT
	mYSQL_TYPE_DOUBLE
	mYSQL_TYPE_NULL
	mYSQL_TYPE_TIMESTAMP
	mYSQL_TYPE_LONGLONG
	mYSQL_TYPE_INT24
	mYSQL_TYPE_DATE
	mYSQL_TYPE_TIME
	mYSQL_TYPE_DATETIME
	mYSQL_TYPE_YEAR
	mYSQL_TYPE_NEWDATE // internal
	mYSQL_TYPE_VARCHAR
	mYSQL_TYPE_BIT
	mYSQL_TYPE_TIMESTAMP2
	mYSQL_TYPE_DATETIME2   // internal
	mYSQL_TYPE_TIME2       // internal
	mYSQL_TYPE_TYPED_ARRAY // for replic
)
const (
	mYSQL_TYPE_INVALID = iota + 243
	mYSQL_TYPE_BOOL
	mYSQL_TYPE_JSON
	mYSQL_TYPE_NEWDECIMAL
	mYSQL_TYPE_ENUM
	mYSQL_TYPE_SET
	mYSQL_TYPE_TINY_BLOB
	mYSQL_TYPE_MEDIUM_BLOB
	mYSQL_TYPE_LONG_BLOB
	mYSQL_TYPE_BLOB
	mYSQL_TYPE_VAR_STRING
	mYSQL_TYPE_STRING
	mYSQL_TYPE_GEOMETRY
)

type payloadBuf struct {
	b    []byte
	head []byte
}

func NewPackBuf() *payloadBuf {
	return &payloadBuf{
		head: make([]byte, 4),
		b:    make([]byte, 0, 1024),
	}
}

var escSeq = map[byte][]byte{
	0:    []byte(`\0`),
	'\'': []byte(`\'`),
	'"':  []byte(`\"`),
	'\b': []byte(`\b`),
	'\n': []byte(`\n`),
	'\r': []byte(`\r`),
	'\t': []byte(`\t`),
	26:   []byte(`\z`),
	'\\': []byte(`\\`),
	'%':  []byte(`\%`),
	'_':  []byte(`\_`),
}

func (buf *payloadBuf) WriteEscaped(c byte) {
	b, ok := escSeq[c]
	if ok {
		buf.write(b)
	} else {
		buf.writeByte(c)
	}
}
func (buf *payloadBuf) writeHead(w io.Writer, l int, secid byte) error {
	calcBytes(l, buf.head[:3])
	buf.head[3] = secid
	_, err := w.Write(buf.head)
	return err
}
func (buf *payloadBuf) readHead(r io.Reader) (l int, secid byte, err error) {
	_, err = r.Read(buf.head)
	if err != nil {
		return
	}
	l = int(calcInt(buf.head[:3]))
	secid = buf.head[3]
	return
}
func (buf *payloadBuf) write(b []byte) {
	buf.b = append(buf.b, b...)
}
func (sess *Session) writeAndSend(w net.Conn, secId byte, bs ...[]byte) {
	for _, b := range bs {
		sess.b = append(sess.b, b...)
	}
	sess.sendPayload(secId)
}
func (buf *payloadBuf) writeByte(c byte) {
	buf.b = append(buf.b, c)
}
func (buf *payloadBuf) writeString(s string) {
	buf.b = append(buf.b, s...)
}
func (sess *Session) sendPayload(secId byte) {
	b := sess.b
	if cap(b) > 5*1024*1024 {
		sess.b = make([]byte, 0, 1024)
	} else {
		sess.reset()
	}

	if len(b) > maxPayload {
		sess.isDead = true
		sess.Destroy()
		panic("you cannot write more than the limit")
	}
	var part []byte
	for i := secId; b != nil; i++ {
		if len(b) >= packetSize {
			b, part = readBytes(b, packetSize)
		} else {
			part = b
			b = nil
		}
		err := sess.writeHead(sess.conn, len(part), i)
		if err == nil {
			_, err = sess.conn.Write(part)
		}
		if err != nil {
			sess.Destroy()
			panic(err)
		}
	}
}
func (sess *Session) readPayload() (b []byte, lastSecid byte) {
	var l int
	var err error
	firstPac := true
	sess.reset()
	defer sess.reset()
	for {
		l, lastSecid, err = sess.readHead(sess.conn)
		if err != nil {
			sess.Destroy()
			panic(err)
		}
		if l > packetSize {
			sess.Destroy()
			panic("Reading more than maxpacket in one read?")
		}
		// never keep buffer larger than 5MB
		if firstPac && l < 1024*1024*5 {
			if cap(b) < l {
				sess.b = make([]byte, 0, l+100)
			}
			b = sess.b
			b = b[:l]
			_, err = io.ReadFull(sess.conn, b)
		} else {
			if len(b)+l > maxPayload {
				panic("too large payload")
			}
			bb := make([]byte, len(b)+l)
			copy(bb, b)
			_, err = io.ReadFull(sess.conn, bb[len(b):])
			b = bb
		}
		if err != nil {
			sess.Destroy()
			panic(err)
		}
		if l < packetSize {
			break
		}
		firstPac = false
	}
	return
}
func (buf *payloadBuf) reset() {
	buf.b = buf.b[:0]
}

const maxPayload = 10 * packetSize

func (sess *Session) Destroy() {
	sess.conn.Close()
	sess.conn = nil
	sess.b = nil
	sess.LastQuery = nil
	sess.payloadBuf = nil
	sess.isDead = true
}

// renew sess by either resetting it if possible, or returnning new one
func (info *DbinfoT) Renew(sess *Session) *Session {
	ok := sess.ResetSession()
	if ok {
		sess.reset()
		sess.LastQuery = sess.LastQuery[:0]
		return sess
	}
	sess.Destroy()
	return info.NewSesstion()
}

// func (info *DbinfoT) GetPool(maxItems int) *Pool {
// 	pool := &Pool{
// 		set:      make(map[*Session]int64, maxItems),
// 		maxItems: maxItems,
// 		dbinfo:   info,
// 	}
// 	misc.ForEver(func() {
// 		var toBeDestroyed []*Session
// 		now := time.Now().UnixMilli()

// 		defer func() {
// 			for _, s := range toBeDestroyed {
// 				s.Destroy()
// 			}
// 		}()
// 		pool.Lock()
// 		defer pool.Unlock()

// 		for sess, since := range pool.set {
// 			if since > 0 {
// 				if now-since > (60 * 1000) {
// 					toBeDestroyed = append(toBeDestroyed, sess)
// 					pool.hanged++

// 				}
// 				continue
// 			}
// 			if since == 0 && now-sess.LastQueryTime.UnixMilli() > (10*1000) {
// 				toBeDestroyed = append(toBeDestroyed, sess)
// 			}
// 		}
// 		for _, sess := range toBeDestroyed {
// 			pool.deletedNo++
// 			pool.totalQueries += sess.Queries
// 			delete(pool.set, sess)
// 		}

// 	}, 10)
// 	return pool
// }
// func (pool *Pool) Put(sess *Session) {

// 	now := time.Now().UnixMilli()
// 	var reseted uint64 = 0
// 	if !sess.isDead && now-sess.lastReset > (10*1000) {

// 		if !sess.ResetSession() {
// 			sess.Destroy()
// 		} else {
// 			reseted = 1
// 		}
// 	}
// 	pool.Lock()
// 	defer pool.Unlock()
// 	since, ok := pool.set[sess]
// 	if !ok {
// 		panic("From where this sess came from ? ")
// 	}
// 	rentTime := now - since - pool.maxRentMs

// 	if rentTime > pool.maxRentMs {
// 		pool.maxRentMs = rentTime
// 	}
// 	if sess.isDead {
// 		delete(pool.set, sess)
// 		pool.deletedNo++
// 		pool.totalQueries += sess.Queries
// 		return
// 	}
// 	pool.reseted += reseted
// 	pool.set[sess] = 0
// 	pool.putNo++
// }

// func (pool *Pool) Get() (got *Session) {

// 	now := time.Now().UnixMilli()
// 	pool.Lock()
// 	defer pool.Unlock()
// 	for sess, takenTime := range pool.set {
// 		if takenTime == 0 {
// 			got = sess
// 			break
// 		}
// 	}
// 	if got == nil { // create new
// 		if len(pool.set) >= pool.maxItems {
// 			pool.maxReachedOn = now
// 			panic("max pool reached, PoolStatue:\n" + pool.String())
// 		}
// 		got = pool.dbinfo.NewSesstion()
// 		pool.createdSess++
// 	}
// 	pool.set[got] = now
// 	pool.getNo++
// 	if pool.maxQueue < len(pool.set) {
// 		pool.maxQueue = len(pool.set)
// 	}
// 	return
// }
// func (pool *Pool) Query(query string, args ...interface{}) Result {
// 	sess := pool.Get()
// 	defer pool.Put(sess)
// 	return sess.Query(query, args...)
// }
// func (pool *Pool) Trans(exec func(*Session)) {
// 	sess := pool.Get()
// 	defer pool.Put(sess)
// 	sess.Begin()
// 	defer func() {
// 		if r := recover(); r != nil {
// 			sess.Rollback()
// 		} else {
// 			sess.Commit()
// 		}
// 	}()
// 	exec(sess)
// }

// type Pool struct {
// 	set map[*Session]int64
// 	sync.Mutex
// 	maxItems     int
// 	dbinfo       *DbinfoT
// 	maxReachedOn int64
// 	getNo        uint64
// 	putNo        uint64
// 	deletedNo    uint64
// 	createdSess  uint64
// 	maxRentMs    int64
// 	totalQueries uint64
// 	maxQueue     int
// 	hanged       uint64
// 	reseted      uint64
// }

// func (pool *Pool) Status() (m [][2]string) {

// 	maxReachedOn := "Never Reached"
// 	if pool.maxReachedOn > 0 {
// 		maxReachedOn = time.UnixMilli(pool.maxReachedOn).String()
// 	}
// 	m = [][2]string{
// 		{"Current Len", misc.ToStr(len(pool.set))},
// 		{"Pool Max Items", misc.ToStr(pool.maxItems)},
// 		{"DB", string(pool.dbinfo.dbName)},
// 		{"max Reached On", maxReachedOn},
// 		{"Put No", misc.ToStr(pool.putNo)},
// 		{"Get No", misc.ToStr(pool.getNo)},
// 		{"Deleted Sessions", misc.ToStr(pool.deletedNo)},
// 		{"Created Sessions", misc.ToStr(pool.createdSess)},
// 		{"Max rented Sess", (time.Millisecond * time.Duration(pool.maxRentMs)).String()},
// 		{"Total Queries", misc.ToStr(pool.totalQueries)},
// 		{"Max Queue Reached", misc.ToStr(pool.maxQueue)},
// 		{"Hanged Sessions", misc.ToStr(pool.hanged)},
// 		{"Reseted Sessions", misc.ToStr(pool.reseted)},
// 	}
// 	return
// }

// func (pool *Pool) String() string {
// 	var w strings.Builder
// 	for _, v := range pool.Status() {
// 		w.WriteString(v[0])
// 		w.WriteString(": ")
// 		w.WriteString(v[1])
// 		w.WriteByte('\n')
// 	}
// 	return w.String()
// }
