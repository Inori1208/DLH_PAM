#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <sys/inotify.h>
#include <limits.h>
#include <openssl/evp.h>
#include <cstring>
#include <ctime>
#include <filesystem> // C++17

// 使用標準命名空間
using namespace std;
// 設定 filesystem 的縮寫，方便後續使用 fs::
namespace fs = filesystem;

// === 設定 Log 檔案路徑 ===
const string LOG_FILE_PATH = "/var/log/pam_guard.log";

// === 設定要監控的目錄 ===
const vector<string> WATCH_DIRS = {
    "/etc/pam.d",
    "/usr/lib/x86_64-linux-gnu/security"
};

// === 全域變數：儲存檔案的基準 Hash ===
// Key: 完整檔案路徑, Value: SHA256 Hash
map<string, string> file_baseline_map;

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

// 寫入 Log 檔案
void log_message(const string& message) {
    ofstream log_file(LOG_FILE_PATH, ios::app);
    if (log_file.is_open()) {
        time_t timestamp = time(NULL);
        log_file << ctime(&timestamp) << "| " << message << endl;
    } else {
        cerr << "ERROR: Cannot write to log: " << LOG_FILE_PATH << endl;
    }
}

// 計算檔案 SHA256 Hash
string calculate_sha256(const string& path) {
    ifstream file(path, ios::binary);
    // 如果檔案無法開啟 (例如已被刪除)，回傳特定字串
    if (!file.is_open()) return "FILE_UNREADABLE";

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(context, md, NULL);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(context, buffer, file.gcount());
    }
    EVP_DigestUpdate(context, buffer, file.gcount());

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_DigestFinal_ex(context, hash, &lengthOfHash);
    EVP_MD_CTX_free(context);

    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// 建立初始基準 (Baseline)
void build_initial_baseline() {
    cout << "Initializing: Building baseline hashes for monitored directories..." << endl;
    log_message("SYSTEM: Starting to build initial baseline hashes.");

    int file_count = 0;
    for (const auto& dir_path : WATCH_DIRS) {
        if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
            string err = "WARNING: Directory not found or invalid: " + dir_path;
            log_message(err);
            cerr << err << endl;
            continue;
        }

        // 遍歷目錄下的所有檔案
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            if (entry.is_regular_file()) {
                string full_path = entry.path().string();
                string hash = calculate_sha256(full_path);
                
                file_baseline_map[full_path] = hash;
                file_count++;
            }
        }
    }
    
    stringstream ss;
    ss << "SYSTEM: Baseline build complete. Monitoring " << file_count << " files.";
    log_message(ss.str());
    cout << ss.str() << endl;
}

int main() {
    // 1. 先建立基準 Hash
    build_initial_baseline();

    // 2. 初始化 inotify
    int fd = inotify_init();
    if (fd < 0) {
        log_message("ERROR: inotify_init failed");
        return 1;
    }

    map<int, string> wd_to_dir; // Watch Descriptor 對應 目錄路徑

    // 3. 加入目錄監控
    for (const auto& dir_path : WATCH_DIRS) {
        int wd = inotify_add_watch(fd, dir_path.c_str(), IN_CREATE | IN_DELETE | IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM);
        
        if (wd != -1) {
            wd_to_dir[wd] = dir_path;
            cout << "Watching directory: " << dir_path << endl;
        } else {
            log_message("ERROR: Failed to watch directory: " + dir_path);
        }
    }

    cout << "Service is running..." << endl;

    // 4. 事件監聽迴圈
    char buffer[EVENT_BUF_LEN];
    while (true) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            log_message("ERROR: Read error from inotify");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            
            if (event->len > 0) {
                if (wd_to_dir.find(event->wd) != wd_to_dir.end()) {
                    string dir = wd_to_dir[event->wd];
                    string filename = event->name;
                    string full_path = dir + "/" + filename;

                    // 過濾暫存檔 (.swp) 或隱藏檔 (.)
                    if (filename[0] != '.' && filename.find(".swp") == string::npos) {
                        
                        // === 檔案新增 (Created / Moved In) ===
                        if ((event->mask & IN_CREATE) || (event->mask & IN_MOVED_TO)) {
                            string new_hash = calculate_sha256(full_path);
                            file_baseline_map[full_path] = new_hash; // 更新白名單
                            
                            stringstream msg;
                            msg << "ALERT: [NEW FILE] " << full_path << " | Hash: " << new_hash;
                            log_message(msg.str());
                            cout << msg.str() << endl;
                        }
                        
                        // === 檔案修改 (Modified / Written) ===
                        else if (event->mask & IN_CLOSE_WRITE) {
                            string new_hash = calculate_sha256(full_path);
                            
                            // 取得舊 Hash
                            string old_hash = "UNKNOWN";
                            if (file_baseline_map.find(full_path) != file_baseline_map.end()) {
                                old_hash = file_baseline_map[full_path];
                            }

                            // **關鍵：Hash 比對**
                            if (new_hash != old_hash) {
                                stringstream msg;
                                msg << "ALERT: [CONTENT CHANGED] " << full_path 
                                    << " | Old: " << old_hash 
                                    << " | New: " << new_hash;
                                log_message(msg.str());
                                cout << msg.str() << endl;

                                // 更新基準值
                                file_baseline_map[full_path] = new_hash;
                            } else {
                                log_message("INFO: File touched but content unchanged: " + full_path);
                            }
                        }

                        // === 檔案刪除 (Deleted / Moved Out) ===
                        else if ((event->mask & IN_DELETE) || (event->mask & IN_MOVED_FROM)) {
                            file_baseline_map.erase(full_path);
                            
                            stringstream msg;
                            msg << "ALERT: [DELETED] " << full_path;
                            log_message(msg.str());
                            cout << msg.str() << endl;
                        }
                    }
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    close(fd);
    return 0;
}