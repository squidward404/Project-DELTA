// src/main.cpp – Project Delta (GUI Only)
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GL/gl.h>
#include <GLFW/glfw3.h>

#include <iostream>
#include <string>
#include <cstring>

// Import our modular DNS logic
#include "DNSresolve.h" 

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#endif

// Input Validation: Allow only domain-safe characters
int InputTextCallback(ImGuiInputTextCallbackData* data) {
    if (data->EventFlag == ImGuiInputTextFlags_CallbackCharFilter) {
        char c = (char)data->EventChar;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '.' || c == '-') return 0;
        return 1;
    }
    return 0;
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

    // Create Window (Title: [Project DELTA])
    GLFWwindow* window = glfwCreateWindow(1000, 650, "[Project DELTA]", nullptr, nullptr);
    if (!window) { glfwTerminate(); return -1; }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // Center Window on Startup
    int monitorCount;
    GLFWmonitor** monitors = glfwGetMonitors(&monitorCount);
    if (monitorCount > 0) {
        const GLFWvidmode* mode = glfwGetVideoMode(monitors[0]);
        int windowW, windowH;
        glfwGetWindowSize(window, &windowW, &windowH);
        glfwSetWindowPos(window, (mode->width - windowW) / 2, (mode->height - windowH) / 2);
    }

    // ImGui Init
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); 
    io.FontGlobalScale = 1.2f; // Larger text

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    char g_inputBuf[256] = "";
    std::string g_results = "Ready. Enter a domain (e.g., google.com)";

    // Main Loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowSize(ImVec2(900, 600), ImGuiCond_FirstUseEver);
        // Inner Window Title: Project DELTA | By ATOMIC
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
                // Sanitize URL input
                size_t start = target.find("://");
                if (start != std::string::npos) target = target.substr(start + 3);
                size_t end = target.find("/");
                if (end != std::string::npos) target = target.substr(0, end);
                
                g_results = "[*] Scanning: " + target + "\n\n" + resolveDomainDetailed(target);
            } else {
                g_results = "[!] Error: Please enter a domain.";
            }
        }

        ImGui::Separator();
        ImGui::Text("Analysis Results:");
        ImGui::BeginChild("ResultsFrame", ImVec2(0, 350), true, ImGuiWindowFlags_HorizontalScrollbar);
        if (!g_results.empty()) ImGui::TextUnformatted(g_results.c_str());
        ImGui::EndChild();

        if (ImGui::Button("Clear")) { g_results = "Ready."; g_inputBuf[0] = 0; }
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
  