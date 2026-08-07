// src/main.cpp – Project Delta v1.4 (Final Titles)
// Compile with: cmake .. && make

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GL/gl.h>
#include <GLFW/glfw3.h>

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sstream>

// --- Platform Specific Headers for DNS ---
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

// --- DNS Resolution Logic ---
std::string resolveDomainDetailed(const std::string& domain) {
    std::ostringstream result;
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;      // Support IPv4 (A) and IPv6 (AAAA)
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;    // Enable CNAME detection

    int status = getaddrinfo(domain.c_str(), NULL, &hints, &res);
    if (status != 0) {
        return "[Error] Resolution failed: " + std::string(gai_strerror(status));
    }

    // 1. Detect CNAME
    if (res->ai_canonname && strcmp(res->ai_canonname, domain.c_str()) != 0) {
        result << "[CNAME] " << domain << "  -->  " << res->ai_canonname << "\n";
    }

    // 2. Iterate and print A / AAAA records
    struct addrinfo* p = res;
    while(p != NULL) {
        char ipstr[INET6_ADDRSTRLEN];
        std::string typeStr = "";

        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            inet_ntop(p->ai_family, &(ipv4->sin_addr), ipstr, sizeof ipstr);
            typeStr = "[A]    "; 
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            inet_ntop(p->ai_family, &(ipv6->sin6_addr), ipstr, sizeof ipstr);
            typeStr = "[AAAA] "; 
        }

        if (!typeStr.empty()) {
            result << typeStr << ipstr << "\n";
        }
        p = p->ai_next;
    }

    freeaddrinfo(res);
    return result.str();
}

// --- Input Validation Callback ---
int InputTextCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
        char c = (char)data->EventChar;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '.' || c == '-') {
            return 0;
        }
        return 1;
    }
    return 0;
}

int main() {
    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return -1;
    #endif

    if (!glfwInit()) {
        fprintf(stderr, "Failed to init GLFW\n");
        return -1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    // 1. OS Window Title: Only "[Project DELTA]"
    GLFWwindow* window = glfwCreateWindow(1000, 650, "[Project DELTA]", nullptr, nullptr);
    if (!window) { glfwTerminate(); return -1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // --- CENTER WINDOW ON STARTUP ---
    int monitorCount;
    GLFWmonitor** monitors = glfwGetMonitors(&monitorCount);
    if (monitorCount > 0) {
        const GLFWvidmode* mode = glfwGetVideoMode(monitors[0]);
        int windowW, windowH;
        glfwGetWindowSize(window, &windowW, &windowH);
        glfwSetWindowPos(window, (mode->width - windowW) / 2, (mode->height - windowH) / 2);
    }
    // --------------------------------

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.FontGlobalScale = 1.2f;

    const char* glsl_version = "#version 130";
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    char g_inputBuf[256] = "";
    std::string g_results = "Ready. Enter a domain (e.g., google.com)";

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
        
        // 2. Inner Window Title: "Project DELTA | By ATOMIC"
        ImGui::Begin("Project DELTA | By ATOMIC", nullptr, ImGuiWindowFlags_NoCollapse);

        ImGui::Text("Target Domain:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##DomainInput", g_inputBuf, sizeof(g_inputBuf), 
                         ImGuiInputTextFlags_CallbackCharFilter, InputTextCallback);
        ImGui::SameLine();

        if (ImGui::Button("Resolve DNS", ImVec2(120, 0))) {
            std::string target(g_inputBuf);
            if (!target.empty()) {
                size_t start = target.find("://");
                if (start != std::string::npos) target = target.substr(start + 3);
                size_t end = target.find("/");
                if (end != std::string::npos) target = target.substr(0, end);
                if (target.empty()) target = "Invalid Domain";

                g_results = "[*] Scanning: " + target + "\n\n" + resolveDomainDetailed(target);
            } else {
                g_results = "[!] Error: Please enter a domain.";
            }
        }

        ImGui::Separator();

        ImGui::Text("Analysis Results:");
        ImGui::BeginChild("ResultsFrame", ImVec2(0, 350), true, ImGuiWindowFlags_HorizontalScrollbar);
        
        if (!g_results.empty()) {
            ImGui::TextUnformatted(g_results.c_str());
        }
        
        ImGui::EndChild();

        if (ImGui::Button("Clear")) { 
            g_results = "Ready."; 
            g_inputBuf[0] = 0; 
        }
        ImGui::SameLine();
        if (ImGui::Button("Exit")) {
            glfwSetWindowShouldClose(window, true);
        }

        ImGui::End();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.05f, 0.05f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    #ifdef _WIN32
    WSACleanup();
    #endif
    return 0;
}   