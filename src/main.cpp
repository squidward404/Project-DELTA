// src/main.cpp – Project Delta v1.1 (Real DNS + Improved GUI)

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

// Platform specific includes for DNS
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

// --- REAL DNS IMPLEMENTATION ---
std::vector<std::string> resolveDomainIPs(const std::string& domain) {
    std::vector<std::string> ips;
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(domain.c_str(), NULL, &hints, &res)) != 0) {
        return {"[Error] Could not resolve: " + std::string(gai_strerror(status))};
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        ips.push_back(std::string(ipstr));
    }

    freeaddrinfo(res);
    return ips;
}

// --- GUI HELPERS ---
// Simple callback to allow only valid domain chars
int InputTextCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
        char c = (char)data->EventChar;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '.' || c == '-') {
            return 0;
        }
        return 1; // Block character
    }
    return 0;
}

int main() {
    // Initialize Socket Lib (Windows only)
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif

    if (!glfwInit()) return -1;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "[Project DELTA] - DNS Recon", nullptr, nullptr);
    if (!window) { glfwTerminate(); return -1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    
    // FIX 1: Font Scaling for better visibility
    io.FontGlobalScale = 1.2f; 

    const char* glsl_version = "#version 130";
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    char g_inputBuf[256] = "";
    std::string g_results = "";
    bool g_running = false;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // FIX 2: Proper Window Sizing and Styling
        ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowPos(ImVec2(200, 100), ImGuiCond_FirstUseEver);

        ImGui::Begin("Project DELTA // DNS Intelligence", nullptr, ImGuiWindowFlags_NoCollapse);

        ImGui::Text("Enter Target Domain:");
        ImGui::SameLine();
        // FIX 3: Input Validation and larger input field
        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##DomainInput", g_inputBuf, sizeof(g_inputBuf), 
                         ImGuiInputTextFlags_CallbackCharFilter, InputTextCallback);

        ImGui::SameLine();
        if (ImGui::Button("Resolve IP", ImVec2(120, 0))) {
            std::string target(g_inputBuf);
            if (!target.empty()) {
                g_running = true;
                g_results = "[*] Resolving " + target + "...\n\n";
                
                auto ips = resolveDomainIPs(target);
                
                g_results += "[+] DNS Records Found:\n";
                for (const auto& ip : ips) {
                    g_results += "    - " + ip + "\n";
                }
                g_running = false;
            } else {
                g_results = "[!] Error: Please enter a valid domain.";
            }
        }

        ImGui::Separator();

        // Results Area
        ImGui::Text("Analysis Results:");
        ImGui::BeginChild("ResultsFrame", ImVec2(0, 300), true, ImGuiWindowFlags_HorizontalScrollbar);
        if (!g_results.empty()) {
            ImGui::TextUnformatted(g_results.c_str());
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(100, 100, 100, 255));
            ImGui::Text("Waiting for input...");
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();

        if (ImGui::Button("Clear")) {
            g_results.clear();
            g_inputBuf[0] = 0;
        }
        ImGui::SameLine();
        if (ImGui::Button("Exit")) {
            glfwSetWindowShouldClose(window, true);
        }

        ImGui::End();

        // Rendering
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