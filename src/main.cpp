// src/main.cpp – Project DELTA (Full Suite: DNS + Network Scanner)
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GL/gl.h>
#include <GLFW/glfw3.h>

#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <vector>
#include <atomic>

// Import modular logic
#include "DNSresolve.h" 
#include "NetworkScanner.h" 

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
#endif

// --- Input Validation Callbacks ---
int InputTextCallbackDomain(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
        char c = (char)data->EventChar;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '.' || c == '-') return 0;
        return 1;
    }
    return 0;
}

int InputTextCallbackIP(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
        char c = (char)data->EventChar;
        if ((c >= '0' && c <= '9') || c == '.') return 0;
        return 1;
    }
    return 0;
}

void CenterWindow(GLFWwindow* window) {
    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
    if (!monitor) return;

    const GLFWvidmode* mode = glfwGetVideoMode(monitor);
    if (!mode) return;

    int monitorX, monitorY;
    glfwGetMonitorPos(monitor, &monitorX, &monitorY);

    int windowW, windowH;
    glfwGetWindowSize(window, &windowW, &windowH);

    glfwSetWindowPos(
        window,
        monitorX + (mode->width - windowW) / 2,
        monitorY + (mode->height - windowH) / 2
    );
}

int main() {
    // Winsock Init (Windows)
    #ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return -1;
    #endif

    // GLFW Init
    if (!glfwInit()) return -1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1440, 900, "[Project DELTA]", nullptr, nullptr);
    if (!window) { glfwTerminate(); return -1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);
    glfwMaximizeWindow(window);

    // Center Window
    CenterWindow(window);

    // ImGui Init
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); 
    io.FontGlobalScale = 1.2f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // --- App State ---
    char g_domainBuf[256] = "";
    char g_ipBuf[256] = "127.0.0.1";
    std::string g_results = "Ready. Select a tool.";
    std::atomic<bool> g_isScanning{false};

    // Main Loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowPos(
            ImGui::GetMainViewport()->GetCenter(),
            ImGuiCond_Always,
            ImVec2(0.5f, 0.5f)
        );
        ImGui::Begin("Project DELTA | By ATOMIC", nullptr, ImGuiWindowFlags_NoCollapse);

        // --- TAB BAR SYSTEM ---
        if (ImGui::BeginTabBar("ToolTabs")) {
            
            // === TAB 1: DNS RESOLVER ===
            if (ImGui::BeginTabItem("DNS Resolver")) {
                ImGui::Text("Target Domain:");
                ImGui::SameLine();
                ImGui::SetNextItemWidth(300);
                ImGui::InputText("##DomainInput", g_domainBuf, sizeof(g_domainBuf), 
                                 ImGuiInputTextFlags_CallbackCharFilter, InputTextCallbackDomain);
                ImGui::SameLine();

                if (ImGui::Button("Resolve DNS", ImVec2(120, 0))) {
                    std::string target(g_domainBuf);
                    if (!target.empty()) {
                        size_t start = target.find("://");
                        if (start != std::string::npos) target = target.substr(start + 3);
                        size_t end = target.find("/");
                        if (end != std::string::npos) target = target.substr(0, end);
                        
                        g_results = "* Resolving: " + target + "\n\n" + resolveDomainDetailed(target);
                    } else {
                        g_results = "* Error: Please enter a domain.";
                    }
                }
                ImGui::EndTabItem();
            }

            // === TAB 2: NETWORK SCANNER ===
            if (ImGui::BeginTabItem("Network Scanner")) {
                ImGui::TextUnformatted("Scan target");
                ImGui::SetNextItemWidth(-1);
                ImGui::InputText("##IPInput", g_ipBuf, sizeof(g_ipBuf), 
                                 ImGuiInputTextFlags_CallbackCharFilter, InputTextCallbackIP);

                ImGui::Spacing();
                ImGui::TextUnformatted("Throttle control");

                static int throttle_ms = 50;
                ImGui::SetNextItemWidth(-1);
                ImGui::SliderInt("##Throttle", &throttle_ms, 0, 500);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Prevents overheating & router crashes");

                ImGui::Spacing();
                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
                if (ImGui::Button("Start", ImVec2(-1, 36))) {
                    if (!g_isScanning.load()) {
                        std::string targetIP(g_ipBuf);
                        if (!targetIP.empty()) {
                            int throttle_value = throttle_ms;
                            g_isScanning.store(true);
                            g_results = "* Initializing Network Scan on " + targetIP + ".../\n";
                            g_results += "* Throttle: " + std::to_string(throttle_value) + "ms\n\n";
                            
                            std::thread([targetIP, &g_results, &g_isScanning, throttle_value]() {
                                // Broader network scan profile for deeper service discovery
                                std::vector<int> scanPorts = {
                                    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
                                    445, 554, 587, 631, 993, 995, 1433, 1521, 2049,
                                    3306, 3389, 5432, 5900, 6379, 8080, 8443, 1883,
                                    27017, 5000, 9000, 9200
                                };
                                
                                std::string scanOutput = scanTargetIntelligent(targetIP, scanPorts, throttle_value);
                                g_results = scanOutput;
                                g_isScanning.store(false);
                            }).detach();
                        } else {
                            g_results = "* Error: Please enter a valid IP.";
                        }
                    } else {
                        g_results = "* Scan already in progress...";
                    }
                }
                ImGui::PopStyleVar();
                
                if (g_isScanning.load()) {
                    ImGui::Spacing();
                    ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.0f, 1.0f), "Scanning...");
                }
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::Separator();
        ImGui::Text("Analysis Results:");
        ImGui::BeginChild("ResultsFrame", ImVec2(0, 350), true, ImGuiWindowFlags_HorizontalScrollbar);
        if (!g_results.empty()) ImGui::TextUnformatted(g_results.c_str());
        ImGui::EndChild();

        // Footer
        if (ImGui::Button("Clear")) { g_results = "Ready."; }
        ImGui::SameLine();
        if (ImGui::Button("Exit")) glfwSetWindowShouldClose(window, true);

        ImGui::End();

        // Render
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.05f, 0.05f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // Cleanup
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