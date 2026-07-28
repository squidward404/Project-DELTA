// src/main.cpp – fully standalone imgui+glfw context

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GL/gl.h>
#include <GLFW/glfw3.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <iostream>
#include <string>
#include <vector>

// Forward declarations
std::vector<std::string> hackertargetHostSearch(const std::string& domain);
std::vector<std::string> findSubdomains(const std::string& domain);
void scanOpenPorts(const std::string& ip);

static std::string g_results = "";
static char g_inputBuf[256] = "";
static bool g_reconRunning = false;

// --- MOCK IMPLEMENTATIONS (So the code compiles for now) ---
std::vector<std::string> hackertargetHostSearch(const std::string& domain) {
    return {"192.168.1.10", "10.0.0.5"}; // Replace with real API logic later
}

std::vector<std::string> findSubdomains(const std::string& domain) {
    return {"www." + domain, "api." + domain, "dev." + domain}; // Replace with real logic
}

void scanOpenPorts(const std::string& ip) {
    std::cout << "[*] Scanning ports on " << ip << " (Mock)..." << std::endl;
}
// -----------------------------------------------------------

int main() {
    if (!glfwInit()) {
        fprintf(stderr, "glfw failed to init...\n");
        return -1;
    }

    // Use OpenGL 3.2 Core Profile (Linux compatible)
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    GLFWwindow* window = glfwCreateWindow(1200, 800, "[project-DELTA] - v1.0.", nullptr, nullptr);

    if (!window) {
        fprintf(stderr, "failed creating window...\n");
        glfwTerminate();
        return -1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    
    const char* glsl_version = "#version 130"; // Linux default
    
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    bool show_demo_window = false;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // === MAIN WINDOW === //
        ImGui::Begin("CloudFlare Ripper v-FREE");

        ImGui::Text("Target Domain:");
        ImGui::InputTextWithHint("##input", "e.g., target.com", g_inputBuf, sizeof(g_inputBuf));
        
        if (ImGui::Button("Unmask Real IP")) {
            g_results = "";
            std::string target(g_inputBuf);
            if (!target.empty()) {
                g_reconRunning = true;

                auto ips = hackertargetHostSearch(target);
                g_results += "[+] Found following possible backends:\n\n";
                for(auto& ip : ips) {
                    g_results += "- Possible backend IP: " + ip + "\n";
                }

                auto subs = findSubdomains(target);
                g_results += "\n[+] Subdomains discovered:\n\n";
                for(auto& sub : subs) {
                    g_results += "- " + sub + "\n";
                }
            }
        }

        if (!g_results.empty()) {
            ImGui::SetNextWindowSize(ImVec2(700, 450), ImGuiCond_Once);
            static bool open = true;
            if(open) {
                ImGui::BeginChild("Results", ImVec2(680, 420), true);
                ImGui::TextUnformatted(g_results.c_str());
                ImGui::EndChild();
            }
        }

        if(ImGui::Button("Clear Results")) {
            g_results.clear();
        }

        if(ImGui::CollapsingHeader("Debug Tools")) {
            if(ImGui::Button("Run Port Scan")) {
                auto ips = hackertargetHostSearch(std::string(g_inputBuf));
                if (!ips.empty()) {
                    scanOpenPorts(ips[0]);
                }
            }
        }

        if(ImGui::Checkbox("Show Demo Window", &show_demo_window)) {
            // toggleable imgui demo
        }

        ImGui::End();

        if(show_demo_window) {
            ImGui::ShowDemoWindow(&show_demo_window);
        }

        // === RENDERING === //
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h); // FIXED TYPO
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.15f, 0.9f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData()); 
        glfwSwapBuffers(window); 
    }
    
    // === CLEANUP === //
    ImGui_ImplOpenGL3_Shutdown();       
    ImGui_ImplGlfw_Shutdown();          
    ImGui::DestroyContext();            

    glfwDestroyWindow(window);          
    glfwTerminate();                    

    return 0;                           
}