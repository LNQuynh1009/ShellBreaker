  ---
  PHẦN I — NỀN TẢNG KIẾN THỨC
  
  Slide A1 — Webshell là gì?
  - Đoạn code độc hại được tải lên server web, cho phép attacker thực thi lệnh từ xa qua HTTP
  - File-based webshell: tồn tại dưới dạng file (.jsp, .php, .aspx) trên disk
  - Phát hiện truyền thống: scan file, so khớp signature, hash blacklist 

  Slide A2 — Memory Webshell (Fileless) là gì?
  - Không ghi file — inject trực tiếp vào JVM heap tại runtime
  - Tận dụng Java Servlet API: đăng ký Filter / Servlet / Listener / Valve / Spring Interceptor động
  - Khi server restart → mất, nhưng attacker thường có persistence riêng
  - Tại sao nguy hiểm hơn: không có file để scan, không có inode, EDR/AV không bắt được
  
  Slide A3 — Cơ chế injection của Memory Webshell
  - Sơ đồ luồng: HTTP Request → Attacker gửi payload → ClassLoader.defineClass() → inject Filter/Servlet vào StandardContext của Tomcat → webshell
  hoạt động trên mọi request tiếp theo
  - 9 loại injection vector: Filter, Listener, Servlet, Spring MVC Controller, Spring Interceptor, Tomcat Valve, ClassLoader, Java Agent, WebSocket
  - Mỗi loại implement interface khác nhau → phải nhận biết được tất cả
  
  Slide A4 — Tại sao tool hiện tại không đủ?

  ┌────────────────┬─────────────────────────────┬──────────────────────────────────┐
  │      Tool      │         Phương pháp         │             Điểm yếu             │
  ├────────────────┼─────────────────────────────┼──────────────────────────────────┤
  │ copagent       │ Rule tĩnh (interface check) │ Bỏ sót biến thể mới, recall thấp │
  ├────────────────┼─────────────────────────────┼──────────────────────────────────┤
  │ JShellDetector │ Signature matching          │ Chỉ file-based                   │
  ├────────────────┼─────────────────────────────┼──────────────────────────────────┤
  │ OpenRASP       │ RASP hook runtime           │ Nặng, nhiều false positive       │
  ├────────────────┼─────────────────────────────┼──────────────────────────────────┤
  │ ShellBreaker   │ ML + Rule hybrid            │ → đây là đóng góp                │
  └────────────────┴─────────────────────────────┴──────────────────────────────────┘

  ---
  PHẦN II — CƠ SỞ NGHIÊN CỨU

  Slide B1 — Tại sao dùng Opcode?
  - Bytecode JVM là ngôn ngữ trung gian — ngôn ngữ nguồn không quan trọng, obfuscate tên biến cũng không ảnh hưởng
  - Opcode sequence phản ánh hành vi thực sự của class
  - Nghiên cứu nền: N-gram opcode đã được dùng thành công trong malware detection từ Schultz et al. (2001), Moskovitch et al. (2008)
  - Bằng chứng: các webshell dù được obfuscate tên, vẫn phải gọi invokevirtual, checkcast, aastore theo pattern nhất định khi manipulate
  reflection/classloader

  Slide B2 — Paper chính: GAShellBreaker (Electronics MDPI, 2025)
  - Đề xuất dùng opcode unigram + bigram từ .class bytecode để phát hiện JSP webshell
  - Kết quả paper: F1 > 0.98 trên file-based webshell
  - ShellBreaker extends: áp dụng pipeline này cho fileless/memory webshell (paper gốc không cover)
  - Mở rộng feature: thêm metadata 10 chiều (call patterns, class structure)
  
  Slide B3 — Paper bổ trợ: Pu et al. (2022) — BERT for JSP Webshell
  - Dùng BERT embedding trên source code JSP → detect webshell
  - Chứng minh: semantic feature của code (không chỉ syntax) có khả năng phân biệt webshell
  - ShellBreaker dùng opcode thay vì source (vì memory webshell không có source) — cùng insight, khác input
  
  Slide B4 — Lý do chọn XGBoost thay vì Deep Learning
  - Sparse high-dim vector (22,360 chiều, mostly zero) → XGBoost xử lý tốt hơn DNN
  - Interpretable: feature importance cho thấy bigram nào là dấu hiệu chính
  - So sánh nội bộ: ResNet50 (image-based bytecode visualization) → XGBoost thắng về tốc độ, không cần GPU, F1 tương đương
  - Phù hợp production: inference < 50ms/file
  
  Slide B5 — Rule-based layer: c0ny1/java-memshell-scanner
  - Công cụ forensic của c0ny1 (widely used trong incident response) — scan JVM heap tìm suspicious class
  - ShellBreaker học từ rule của c0ny1 và mở rộng: thêm Tomcat Valve, Spring WebSocket, Java Agent interface
  - Weighted scoring thay vì binary → kết hợp được với ML score
  - Bằng chứng rule hoạt động: c0ny1 được dùng trong nhiều case study tại các CERT Trung Quốc

Slide C1 — Tổng quan pipeline (1 slide sơ đồ)
  [Thu thập data] → [Compile/Filter] → [Trích xuất feature]
         → [Train XGBoost] → [Rule-based layer] → [Hybrid verdict]
                                                         ↓
                                                [FastAPI / Lab integration]
  Mỗi bước dưới đây là 1-2 slide giải thích.    

  ---
  Slide C2 — Thu thập dataset
  - Webshell: clone từ GitHub (java-memshell-generator, su18/MemoryShell, rebeyond/memShell, changheluor007/MemShell, wsMemShell, MemoryShellLearn)
  - Benign train: 18 repo thực tế — Tomcat, Spring, Netty, Hibernate... (cùng domain với target)
  - Benign test: tải JAR từ Maven Central — domain mới, chưa bao giờ thấy lúc train
  - Fileless test: 82 class, held out hoàn toàn — không vào train, không vào val
  - Tại sao tách như vậy: tránh data leakage, đánh giá đúng khả năng generalize

  Slide C3 — Xử lý data
  - Compile benign repo → .class bằng javac
  - Dedup bằng MD5 hash — loại class trùng (nhiều repo dùng chung lib)
  - Phân loại webshell: file-based (có .java source) vs fileless (chỉ có .class, inject qua ClassLoader)
  - Kết quả: 876 webshell_file + 82 fileless + 4,136 benign + 500 benign_test

  ---
  Slide C4 — Trích xuất Opcode (bước quan trọng nhất)
  - Chạy javap -c -verbose trên từng .class → disassemble bytecode thành text
  - Parse lấy opcode sequence (bỏ operand, chỉ lấy mnemonic)
  - Collapse variants: iload_0, iload_1, iload_2, iload_3 → iload (149 canonical opcodes)
  - Tại sao collapse: tránh spurious bigram từ index cụ thể, focus vào pattern hành vi
  
  Slide C5 — Feature Vector (22,360 chiều)

  ┌──────────┬────────┬───────────────────────────────────────────────────────────────────────────────────────────┐
  │   Nhóm   │ Chiều  │                                         Nội dung                                          │
  ├──────────┼────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
  │ Unigram  │ 149    │ Tần suất từng opcode                                                                      │
  ├──────────┼────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
  │ Bigram   │ 22,201 │ Tần suất từng cặp opcode liên tiếp                                                        │
  ├──────────┼────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
  │ Metadata │ 10     │ Số lần gọi invokevirtual, checkcast, aastore, số method, số interface, độ dài bytecode... │
  └──────────┴────────┴───────────────────────────────────────────────────────────────────────────────────────────┘

  - Lưu dưới dạng sparse matrix (scipy) — 99% là zero, tiết kiệm RAM
  - Tổng: ~5,500 class × 22,360 dim = vẫn fit RAM nhờ sparse

  ---
  Slide C6 — Training XGBoost
  - Class imbalance: 876 webshell vs 4,136 benign → scale_pos_weight = 4136/876 ≈ 4.7
  - 3 independent runs, shuffle khác nhau → lấy trung bình metric (đúng methodology của paper)
  - Threshold optimization: tìm threshold thấp nhất sao cho val precision ≥ 0.50, maximize recall
    - Default threshold 0.50 → precision cao, recall vừa
    - High-recall threshold 0.105 → recall 100% (dùng cho alert tiers thấp hơn)
  - Train time: ~60 phút feature extraction + ~5 phút XGBoost (CPU, no GPU)

  Slide C7 — Rule-based Layer
  - Chạy song song với ML, độc lập
  - Kiểm tra bytecode/classname cho:
    - Implement interface nguy hiểm: javax.servlet.Filter, Servlet, ServletContextListener, org.apache.catalina.Valve, HandlerInterceptor,
  ClassFileTransformer... 
    - Gọi: Runtime.exec(), defineClass(), ProcessBuilder
    - Tool fingerprint: tên class giống pattern của known tools (MemShell, Godzilla, Behinder)
  - Mỗi dấu hiệu có weight khác nhau → tổng điểm → HIGH / MEDIUM / LOW / NONE

  Slide C8 — Hybrid Verdict Logic
  Rule = HIGH  AND  ML ≥ 0.50  →  CONFIRMED
  Rule = HIGH  OR   ML ≥ 0.85  →  HIGH
  Rule = MED   OR   ML ≥ 0.50  →  MEDIUM
  Otherwise                    →  BENIGN
  - Tại sao cần kết hợp: ML alone recall = 26.3% trên fileless (chưa thấy lúc train) → rule cứu
  - Rule alone: nhiều false positive, không có score → không rank được
  - Hybrid: precision 0.976, recall 1.000, F1 0.988
  
  ---
  Slide C9 — Inference API
  - FastAPI server, port 8080
  - Endpoint: POST /analyze nhận file .class → trả JSON
  {
    "verdict": "CONFIRMED",
    "ml_score": 0.94,
    "rule_tier": "HIGH",
    "rule_score": 85,
    "injection_type": "Filter",
    "top_opcodes": ["invokevirtual", "checkcast", "aastore"],
    "matched_rules": ["implements_filter", "define_class_call"]
  } 
  - CLI mode: python 05_inference_api.py /path/to/File.class → kết quả ngay

  Slide C10 — Lab Integration
  - Monitor Tomcat work dir (/work/Catalina/localhost/) → detect compiled JSP .class realtime
  - Mỗi detection → append vào detections.jsonl (forensic log)
  - CONFIRMED / HIGH → gửi email cảnh báo
  - Mọi event → gửi vào Splunk (HEC) → dashboard realtime, search, alert rule trong Splunk
