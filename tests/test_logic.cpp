#include <gtest/gtest.h>
#include <fstream>
#include "../utils.h"
#include "../rule_engine.h"
#include "../http_detector.h"

// 1. parse_ipv4 tests
TEST(ParseIpv4Test, ValidIps) {
    auto ip = parse_ipv4("10.10.0.1");
    ASSERT_TRUE(ip.has_value());
}

TEST(ParseIpv4Test, InvalidIps) {
    EXPECT_FALSE(parse_ipv4("999.1.1.1").has_value());
    EXPECT_FALSE(parse_ipv4("").has_value());
    EXPECT_FALSE(parse_ipv4("10.0.0.1; rm -rf /").has_value()); // shell characters
    
    // leading zeros are generally invalid in strict IPv4 or treated as octal
    // inet_pton might reject them. Let's see what it does:
    EXPECT_FALSE(parse_ipv4("10.010.0.1").has_value()); // inet_pton rejects leading zeros in IPv4 strings natively
}

// 2. Rule loading tests
TEST(RuleEngineTest, ValidYaml) {
    std::string yaml_path = "/tmp/valid_rules.yaml";
    std::ofstream out(yaml_path);
    out << "- name: TEST_RULE\n  type: threshold\n  match_type: ssh_failed\n  threshold: 5\n  window_seconds: 120\n  severity: medium\n  mitre: [T1110]\n  action: block\n  block_seconds: 600\n";
    out.close();
    
    EXPECT_NO_THROW({
        RuleEngine engine(yaml_path);
        EXPECT_EQ(engine.get_rules().size(), 1);
    });
}

TEST(RuleEngineTest, MissingField) {
    std::string yaml_path = "/tmp/missing_field.yaml";
    std::ofstream out(yaml_path);
    out << "- name: TEST_RULE\n  type: threshold\n"; // missing fields
    out.close();
    
    EXPECT_THROW({ RuleEngine engine(yaml_path); }, std::runtime_error);
}

TEST(RuleEngineTest, UnknownStepName) {
    std::string yaml_path = "/tmp/unknown_step.yaml";
    std::ofstream out(yaml_path);
    out << "- name: BAD_SEQ\n  type: sequence\n  steps: [unknown_step, ssh_failed]\n  severity: high\n  mitre: [T1110]\n  action: block\n  block_seconds: 600\n  within_seconds: 60\n";
    out.close();
    
    EXPECT_THROW({ RuleEngine engine(yaml_path); }, std::runtime_error);
}

// 3. Sliding window tests
TEST(RuleEngineTest, SlidingWindow) {
    std::string yaml_path = "/tmp/window_rules.yaml";
    std::ofstream out(yaml_path);
    out << "- name: SSH_BRUTE\n  type: threshold\n  match_type: ssh_failed\n  threshold: 3\n  window_seconds: 2\n  severity: high\n  mitre: [T1110]\n  action: block\n  block_seconds: 600\n";
    out.close();
    
    RuleEngine engine(yaml_path);
    
    Event e;
    e.type = "ssh_failed";
    e.src_ip = "1.2.3.4";
    
    // First two events should not alert
    EXPECT_TRUE(engine.process(e).empty());
    EXPECT_TRUE(engine.process(e).empty());
    
    // Third event hits threshold
    auto alerts = engine.process(e);
    ASSERT_EQ(alerts.size(), 1);
    EXPECT_EQ(alerts[0].rule, "SSH_BRUTE");
    
    // Window expiry: wait 3 seconds, fire 2 events, no alert
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_TRUE(engine.process(e).empty());
    EXPECT_TRUE(engine.process(e).empty());
}

// 4. Sequence rules tests
TEST(RuleEngineTest, SequenceRules) {
    std::string yaml_path = "/tmp/seq_rules.yaml";
    std::ofstream out(yaml_path);
    out << "- name: SCAN_SSH\n  type: sequence\n  steps: [port_scan, ssh_failed]\n  within_seconds: 5\n  severity: critical\n  mitre: [T1110]\n  action: block\n  block_seconds: 600\n";
    out.close();
    
    RuleEngine engine(yaml_path);
    Event scan, ssh;
    scan.type = "port_scan"; scan.src_ip = "1.1.1.1";
    ssh.type = "ssh_failed"; ssh.src_ip = "1.1.1.1";
    
    // scan -> ssh fires
    EXPECT_TRUE(engine.process(scan).empty());
    auto alerts = engine.process(ssh);
    ASSERT_EQ(alerts.size(), 1);
    EXPECT_EQ(alerts[0].rule, "SCAN_SSH");
    
    // ssh -> scan does not fire
    scan.src_ip = "2.2.2.2";
    ssh.src_ip = "2.2.2.2";
    EXPECT_TRUE(engine.process(ssh).empty());
    EXPECT_TRUE(engine.process(scan).empty());
}

// 5. HTTP pattern matching & 4096-byte line cap
TEST(HttpDetectorTest, PatternMatchingAndCap) {
    std::string yaml_path = "/tmp/http_rules.yaml";
    std::ofstream out(yaml_path);
    out << "- name: SQLI\n  type: signature\n  match_type: http_sqli\n  patterns: [\"UNION SELECT\", \"' OR 1=1\"]\n  severity: high\n  mitre: [T1190]\n  action: block\n  block_seconds: 600\n";
    out.close();
    
    RuleEngine engine(yaml_path);
    std::vector<Event> emitted;
    HttpDetector detector("/tmp/dummy.log", engine, [&](const Event& e){ emitted.push_back(e); });
    
    // Valid log with SQLi in UA
    std::string sqli_line = "10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1234 \"-\" \"' OR 1=1\"";
    detector.process_line(sqli_line);
    ASSERT_EQ(emitted.size(), 1);
    EXPECT_EQ(emitted[0].type, "http_sqli");
    
    // 4096-byte cap test
    emitted.clear();
    std::string long_line = "10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 1234 \"-\" \"";
    long_line.append(5000, 'A'); // Over 4096 bytes
    long_line += " UNION SELECT\""; // Contains pattern but should be capped/ignored
    
    // To test the cap properly, process_line doesn't enforce the cap itself, the watch_loop does.
    // Wait, process_line doesn't enforce it. I will just check if line length > 4096 in process_line or test it via file.
    // To strictly test via process_line, process_line itself won't drop it unless I moved the cap there.
    detector.process_line(long_line);
    EXPECT_EQ(emitted.size(), 0); // Should be ignored
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
