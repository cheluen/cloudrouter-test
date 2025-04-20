import { Router } from 'itty-router';

// 创建路由器
const router = Router();

// --- 全局变量 ---
let apiKeys = []; // 缓存 API 密钥
let currentKeyIndex = 0;
let lastHealthCheck = 0;
let adminPasswordHash = null; // 缓存管理员密码哈希
let adminHtmlContent = null; // 缓存 admin.html 内容

// OpenRouter API 基础 URL
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';
const KV_KEYS = {
  API_KEYS: 'api_keys',
  ADMIN_PASSWORD_HASH: 'admin_password_hash',
};

// --- 辅助函数 ---

// 初始化：从 KV 加载 API 密钥和管理员密码哈希
async function initializeState(env) {
  try {
    const [keysData, passwordHashData] = await Promise.all([
      env.ROUTER_KV.get(KV_KEYS.API_KEYS, { type: 'json' }),
      env.ROUTER_KV.get(KV_KEYS.ADMIN_PASSWORD_HASH, { type: 'string' }),
    ]);

    if (keysData && Array.isArray(keysData)) {
      apiKeys = keysData;
      console.log(`已加载 ${apiKeys.length} 个API密钥`);
    } else {
      apiKeys = [];
      console.log('未找到API密钥');
    }

    if (passwordHashData) {
      adminPasswordHash = passwordHashData;
      console.log('已加载管理员密码哈希');
    } else {
      adminPasswordHash = null;
      console.log('未设置管理员密码');
    }
  } catch (error) {
    console.error('初始化状态失败:', error);
    apiKeys = [];
    adminPasswordHash = null;
  }
}

// 密码哈希函数 (SHA-256)
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

// 验证密码
async function verifyPassword(providedPassword, storedHash) {
  if (!providedPassword || !storedHash) {
    return false;
  }
  const providedHash = await hashPassword(providedPassword);
  return providedHash === storedHash;
}

// 管理员认证中间件
async function requireAdminAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: '未提供认证信息' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  const token = authHeader.substring(7); // 提取密码
  if (!adminPasswordHash) {
    // 应该在调用此中间件之前检查密码是否已设置，但作为安全措施再次检查
    return new Response(JSON.stringify({ error: '管理员密码尚未设置' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  const isValid = await verifyPassword(token, adminPasswordHash);
  if (!isValid) {
    return new Response(JSON.stringify({ error: '无效的管理密码' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // 认证成功，将密码（或标记）附加到请求对象，以便后续路由使用（如果需要）
  request.isAdmin = true;
  request.adminPassword = token; // 存储明文密码以备更改密码时使用
}

// 检查 API 密钥健康状态
async function checkKeyHealth(key) {
  try {
    const response = await fetch(`${OPENROUTER_BASE_URL}/models`, {
      headers: {
        'Authorization': `Bearer ${key.value}`,
        'HTTP-Referer': 'https://cloudrouter.project', // 替换为你喜欢的引用来源
        'X-Title': 'CloudRouter' // 替换为你喜欢的标题
      }
    });
    return response.status === 200;
  } catch (error) {
    console.error(`密钥健康检查失败: ${key.name}`, error);
    return false;
  }
}

// 定期健康检查
async function healthCheck() {
  const now = Date.now();
  // 每 10 分钟执行一次
  if (now - lastHealthCheck < 600000) return;

  lastHealthCheck = now;
  console.log('执行API密钥健康检查');

  const healthPromises = apiKeys.map(async (key, index) => {
    const isHealthy = await checkKeyHealth(key);
    // 直接修改缓存中的状态
    apiKeys[index] = { ...key, isHealthy };
  });

  await Promise.all(healthPromises);
  console.log('API密钥健康检查完成');
}

// 获取下一个可用的 API 密钥（轮询）
function getNextKey() {
  if (apiKeys.length === 0) return null;

  let attempts = 0;
  while (attempts < apiKeys.length) {
    currentKeyIndex = (currentKeyIndex + 1) % apiKeys.length;
    const key = apiKeys[currentKeyIndex];
    // 优先使用健康的密钥，如果没有健康的，则尝试所有密钥
    if (key.isHealthy !== false) {
      return key;
    }
    attempts++;
  }

  // 如果所有密钥都标记为不健康，则按顺序尝试返回第一个
  console.warn('所有API密钥都标记为不健康，尝试使用第一个密钥');
  return apiKeys.length > 0 ? apiKeys[0] : null;
}

// 验证 API 调用访问权限 (OpenAI 兼容端点)
function validateApiAccess(request, env) {
  // 在这个简化版本中，我们允许任何以 'Bearer sk-' 开头的令牌访问
  // 你可以根据需要实现更复杂的逻辑，例如从 KV 验证自定义密钥
  const authHeader = request.headers.get('Authorization');
  return authHeader && authHeader.startsWith('Bearer sk-');
}

// 获取管理页面 HTML 内容 (从 KV 或默认值)
async function getAdminHtml(env) {
    // 尝试从 KV 加载，如果不存在则使用硬编码的 HTML
    // 注意：这里我们不再从 src/admin.html 文件读取，而是直接嵌入
    // 这简化了部署，因为不需要额外的构建步骤或文件处理
    if (!adminHtmlContent) {
        adminHtmlContent = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudRouter 管理面板</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: auto; background-color: #f4f4f4; }
        .container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        h1, h2 { color: #333; }
        button { background-color: #3498db; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; font-size: 14px; transition: background-color 0.3s; margin-right: 5px; }
        button:hover { background-color: #2980b9; }
        button.danger { background-color: #e74c3c; }
        button.danger:hover { background-color: #c0392b; }
        input[type="text"], input[type="password"] { width: calc(100% - 22px); padding: 10px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #f0f0f0; }
        .status { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status.healthy { background-color: #2ecc71; }
        .status.unhealthy { background-color: #e74c3c; }
        .status.unknown { background-color: #95a5a6; }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.4); }
        .modal-content { background-color: #fefefe; margin: 15% auto; padding: 20px; border: 1px solid #888; width: 80%; max-width: 500px; border-radius: 8px; }
        .close-btn { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
        .close-btn:hover, .close-btn:focus { color: black; text-decoration: none; cursor: pointer; }
        .hidden { display: none; }
        #loading { text-align: center; padding: 20px; font-style: italic; color: #666; }
        .error-message { color: red; margin-bottom: 10px; }
        .success-message { color: green; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1>CloudRouter 管理面板</h1>

    <!-- Loading Indicator -->
    <div id="loading">正在加载...</div>

    <!-- Auth Section (Setup/Login) -->
    <div id="authSection" class="container hidden">
        <div id="setupSection" class="hidden">
            <h2>设置管理员密码</h2>
            <p>首次使用，请设置管理员密码。</p>
            <div id="setupError" class="error-message hidden"></div>
            <form id="setupForm">
                <label for="setupPassword">新密码:</label>
                <input type="password" id="setupPassword" required>
                <label for="confirmPassword">确认密码:</label>
                <input type="password" id="confirmPassword" required>
                <button type="submit">设置密码</button>
            </form>
        </div>
        <div id="loginSection" class="hidden">
            <h2>管理员登录</h2>
            <div id="loginError" class="error-message hidden"></div>
            <form id="loginForm">
                <label for="loginPassword">密码:</label>
                <input type="password" id="loginPassword" required>
                <button type="submit">登录</button>
            </form>
        </div>
    </div>

    <!-- Main Content (Visible after login) -->
    <div id="mainContent" class="container hidden">
        <div style="display: flex; justify-content: space-between; align-items: center;">
             <h2>管理</h2>
             <button id="logoutButton">退出登录</button>
        </div>

        <!-- API Key Management -->
        <div class="container">
            <h3>API 密钥管理 (OpenRouter)</h3>
            <div id="apiKeyError" class="error-message hidden"></div>
            <div id="apiKeySuccess" class="success-message hidden"></div>
            <form id="addKeyForm" style="margin-bottom: 15px;">
                <label for="keyName">密钥名称:</label>
                <input type="text" id="keyName" placeholder="例如：My Key 1" required>
                <label for="keyValue">密钥值 (sk-...):</label>
                <input type="password" id="keyValue" required>
                <button type="submit">添加密钥</button>
            </form>
            <h4>现有密钥:</h4>
            <table id="keysTable">
                <thead>
                    <tr>
                        <th>状态</th>
                        <th>名称</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody id="keysList">
                    <tr><td colspan="3">正在加载...</td></tr>
                </tbody>
            </table>
             <button id="refreshKeysButton">刷新密钥状态</button>
        </div>

        <!-- Change Password -->
        <div class="container">
            <h3>修改管理员密码</h3>
            <div id="changePasswordError" class="error-message hidden"></div>
            <div id="changePasswordSuccess" class="success-message hidden"></div>
            <form id="changePasswordForm">
                <label for="currentPassword">当前密码:</label>
                <input type="password" id="currentPassword" required>
                <label for="newPassword">新密码:</label>
                <input type="password" id="newPassword" required>
                <label for="confirmNewPassword">确认新密码:</label>
                <input type="password" id="confirmNewPassword" required>
                <button type="submit">修改密码</button>
            </form>
        </div>

        <!-- Usage Instructions -->
        <div class="container">
             <h3>使用说明</h3>
             <p>将以下地址配置到你的 AI 客户端的 API Base URL:</p>
             <code id="apiUrl"></code>
             <p>使用任何以 <code>sk-</code> 开头的字符串作为 API Key 进行基础验证。</p>
             <p><strong>注意:</strong> 管理员密码仅用于访问此管理面板，不用于 API 调用。</p>
        </div>
    </div>

    <script>
        const apiUrlBase = window.location.origin;
        const adminApiBase = \`\${apiUrlBase}/api/admin\`;
        let adminPassword = null; // Store password in memory for session

        // --- UI Elements ---
        const loadingDiv = document.getElementById('loading');
        const authSection = document.getElementById('authSection');
        const setupSection = document.getElementById('setupSection');
        const loginSection = document.getElementById('loginSection');
        const mainContent = document.getElementById('mainContent');
        const setupForm = document.getElementById('setupForm');
        const loginForm = document.getElementById('loginForm');
        const addKeyForm = document.getElementById('addKeyForm');
        const changePasswordForm = document.getElementById('changePasswordForm');
        const keysList = document.getElementById('keysList');
        const logoutButton = document.getElementById('logoutButton');
        const refreshKeysButton = document.getElementById('refreshKeysButton');
        const apiUrlCode = document.getElementById('apiUrl');

        // --- Message Helpers ---
        function showMessage(elementId, message, isError = true) {
            const el = document.getElementById(elementId);
            el.textContent = message;
            el.className = isError ? 'error-message' : 'success-message';
            el.classList.remove('hidden');
            setTimeout(() => el.classList.add('hidden'), 5000); // Hide after 5s
        }
        const showSetupError = (msg) => showMessage('setupError', msg);
        const showLoginError = (msg) => showMessage('loginError', msg);
        const showApiKeyError = (msg) => showMessage('apiKeyError', msg);
        const showApiKeySuccess = (msg) => showMessage('apiKeySuccess', msg, false);
        const showChangePasswordError = (msg) => showMessage('changePasswordError', msg);
        const showChangePasswordSuccess = (msg) => showMessage('changePasswordSuccess', msg, false);

        // --- API Call Helper ---
        async function apiCall(endpoint, method = 'GET', body = null, requiresAuth = true) {
            const headers = { 'Content-Type': 'application/json' };
            if (requiresAuth) {
                if (!adminPassword) {
                    console.error('Admin password not available for authenticated request');
                    showLogin(); // Force login if auth needed but no password
                    return null; // Indicate failure
                }
                headers['Authorization'] = \`Bearer \${adminPassword}\`;
            }

            const options = { method, headers };
            if (body) {
                options.body = JSON.stringify(body);
            }

            try {
                const response = await fetch(\`\${adminApiBase}\${endpoint}\`, options);
                if (response.status === 401) { // Unauthorized
                    adminPassword = null; // Clear stored password
                    localStorage.removeItem('cloudrouter_admin_password');
                    showLogin();
                    showLoginError('认证失败或会话已过期，请重新登录。');
                    return null; // Indicate failure
                }
                 if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: '未知错误' }));
                    throw new Error(errorData.error || \`HTTP error! status: \${response.status}\`);
                }
                // Handle no content response for DELETE etc.
                 if (response.status === 204) {
                    return { success: true };
                 }
                return await response.json();
            } catch (error) {
                console.error(\`API call failed for \${method} \${endpoint}:\`, error);
                // Display error in the relevant section
                if (endpoint.startsWith('/keys')) showApiKeyError(\`操作失败: \${error.message}\`);
                else if (endpoint.startsWith('/auth/change-password')) showChangePasswordError(\`操作失败: \${error.message}\`);
                else showLoginError(\`操作失败: \${error.message}\`); // Default to login error
                return null; // Indicate failure
            }
        }

        // --- Auth Logic ---
        async function checkAuthStatus() {
            console.log('checkAuthStatus: Starting...');
            loadingDiv.classList.remove('hidden');
            authSection.classList.add('hidden');
            mainContent.classList.add('hidden');

            try {
                // Attempt to retrieve password from localStorage first
                const storedPassword = localStorage.getItem('cloudrouter_admin_password');
                let loggedIn = false;
                console.log('checkAuthStatus: Checking stored password...');

                if (storedPassword) {
                    console.log('checkAuthStatus: Found stored password. Verifying...');
                    adminPassword = storedPassword;
                    // Use apiCall to verify, it has better error handling
                    const loginResponse = await apiCall('/auth/login', 'POST', { password: adminPassword }, false);
                    if (loginResponse && loginResponse.success) {
                        console.log('checkAuthStatus: Stored password verified.');
                        loggedIn = true;
                    } else {
                        console.log('checkAuthStatus: Stored password invalid or verification failed.');
                        adminPassword = null; // Clear invalid stored password
                        localStorage.removeItem('cloudrouter_admin_password');
                        // Don't show login error here, proceed to check setup status
                    }
                } else {
                    console.log('checkAuthStatus: No stored password found.');
                }

                if (loggedIn) {
                    console.log('checkAuthStatus: Logged in. Showing main content...');
                    showMainContent();
                } else {
                    console.log('checkAuthStatus: Not logged in. Checking setup status via /api/admin/auth/status...');
                    // If not logged in via stored password, check if setup is needed
                    let statusData = null;
                    try {
                        const statusResponse = await fetch(\`\${adminApiBase}/auth/status\`);
                        console.log('checkAuthStatus: Status API response status:', statusResponse.status);
                        if (!statusResponse.ok) {
                             // Throw an error if response is not OK (e.g., 500)
                             throw new Error(\`Status check failed with status: \${statusResponse.status}\`);
                        }
                         // Try parsing JSON, might fail if backend returned HTML error page
                        statusData = await statusResponse.json();
                        console.log('checkAuthStatus: Status API response data:', statusData);

                    } catch (fetchError) {
                         console.error('checkAuthStatus: Failed to fetch or parse status API response:', fetchError);
                         // Show login by default if status check fails, assuming password might be set
                         showLogin();
                         showLoginError('无法检查服务器状态，请稍后重试。');
                         loadingDiv.classList.add('hidden'); // Hide loading indicator even on error
                         return; // Stop further execution in this block
                    }


                    if (statusData && statusData.isPasswordSet === false) { // Explicitly check for false
                        console.log('checkAuthStatus: Password not set. Showing setup...');
                        showSetup();
                    } else {
                        // Assume password is set (or status check failed ambiguously)
                        console.log('checkAuthStatus: Password likely set or status unknown. Showing login...');
                        showLogin();
                    }
                }
            } catch (error) {
                // Catch errors from the outer try block (e.g., apiCall errors during login verification)
                console.error('checkAuthStatus: General error during auth check:', error);
                loadingDiv.textContent = '加载管理面板时出错，请刷新页面。';
                // Do not hide loading indicator here, as the error message replaces it.
                return; // Stop execution
            }

            // Ensure loading indicator is hidden if no major error occurred
            console.log('checkAuthStatus: Hiding loading indicator.');
            loadingDiv.classList.add('hidden');
            console.log('checkAuthStatus: Finished.');
        }

        function showSetup() {
            authSection.classList.remove('hidden');
            setupSection.classList.remove('hidden');
            loginSection.classList.add('hidden');
            mainContent.classList.add('hidden');
        }

        function showLogin() {
            authSection.classList.remove('hidden');
            setupSection.classList.add('hidden');
            loginSection.classList.remove('hidden');
            mainContent.classList.add('hidden');
        }

        function showMainContent() {
            authSection.classList.add('hidden');
            mainContent.classList.remove('hidden');
            apiUrlCode.textContent = \`\${apiUrlBase}/v1\`; // Set the API URL display
            loadApiKeys(); // Load keys when showing main content
        }

        setupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('setupPassword').value;
            const confirm = document.getElementById('confirmPassword').value;

            if (password !== confirm) {
                showSetupError('两次输入的密码不匹配。');
                return;
            }
            if (password.length < 8) {
                 showSetupError('密码长度至少需要8位。');
                 return;
            }

            const result = await apiCall('/auth/setup', 'POST', { password }, false); // Setup doesn't require auth
            if (result && result.success) {
                adminPassword = password; // Store password for the session
                localStorage.setItem('cloudrouter_admin_password', password); // Store in localStorage
                showMainContent();
            } else {
                 showSetupError(result?.error || '设置密码失败。');
            }
        });

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = document.getElementById('loginPassword').value;
            const result = await apiCall('/auth/login', 'POST', { password }, false); // Login doesn't require auth initially
             if (result && result.success) {
                adminPassword = password; // Store password for the session
                localStorage.setItem('cloudrouter_admin_password', password); // Store in localStorage
                showMainContent();
            } else {
                showLoginError('登录失败：密码错误。');
            }
        });

        logoutButton.addEventListener('click', () => {
            adminPassword = null;
            localStorage.removeItem('cloudrouter_admin_password');
            showLogin();
        });

        // --- API Key Management Logic ---
        async function loadApiKeys() {
            keysList.innerHTML = '<tr><td colspan="3">正在加载密钥...</td></tr>';
            const result = await apiCall('/keys'); // Requires auth implicitly
            if (result && result.keys) {
                renderApiKeys(result.keys);
            } else if (result === null) {
                 // Error handled by apiCall, maybe show specific message here if needed
                 keysList.innerHTML = '<tr><td colspan="3" style="color: red;">加载密钥失败，请检查登录状态。</td></tr>';
            } else {
                 keysList.innerHTML = '<tr><td colspan="3">没有找到 API 密钥。</td></tr>';
            }
        }

        function renderApiKeys(keys) {
            if (keys.length === 0) {
                keysList.innerHTML = '<tr><td colspan="3">没有找到 API 密钥。请添加。</td></tr>';
                return;
            }
            keysList.innerHTML = keys.map(key => \`
                <tr>
                    <td><span class="status \${key.isHealthy === true ? 'healthy' : (key.isHealthy === false ? 'unhealthy' : 'unknown')}"></span> \${key.isHealthy === true ? '可用' : (key.isHealthy === false ? '不可用' : '未知')}</td>
                    <td>\${escapeHtml(key.name)}</td>
                    <td><button class="danger" onclick="deleteApiKey('\${escapeHtml(key.name)}')">删除</button></td>
                </tr>
            \`).join('');
        }

         // Simple HTML escaping
        function escapeHtml(unsafe) {
            if (!unsafe) return '';
            // Correctly escape HTML special characters
            return unsafe
                 .replace(/&/g, "&")
                 .replace(/</g, "<")
                 .replace(/>/g, ">")
                 .replace(/"/g, """)
                 .replace(/'/g, "&#039;");
        }


        addKeyForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('keyName').value.trim();
            const value = document.getElementById('keyValue').value.trim();

            if (!name || !value) {
                showApiKeyError('密钥名称和值不能为空。');
                return;
            }
             if (!value.startsWith('sk-')) {
                 showApiKeyError('OpenRouter API 密钥通常以 "sk-" 开头。');
                 // Allow submission anyway, but warn
             }

            const result = await apiCall('/keys', 'POST', { name, value });
            if (result && result.success) {
                showApiKeySuccess('API 密钥添加成功！');
                addKeyForm.reset();
                loadApiKeys(); // Refresh list
            }
            // Error handled by apiCall
        });

        async function deleteApiKey(name) {
            if (!confirm(\`确定要删除密钥 "\${name}" 吗？\`)) return;

            const result = await apiCall(\`/keys/\${encodeURIComponent(name)}\`, 'DELETE');
            if (result && result.success) {
                showApiKeySuccess('API 密钥删除成功！');
                loadApiKeys(); // Refresh list
            }
             // Error handled by apiCall
        }

        refreshKeysButton.addEventListener('click', loadApiKeys);


        // --- Change Password Logic ---
        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmNewPassword = document.getElementById('confirmNewPassword').value;

            if (newPassword !== confirmNewPassword) {
                showChangePasswordError('新密码和确认密码不匹配。');
                return;
            }
             if (newPassword.length < 8) {
                 showChangePasswordError('新密码长度至少需要8位。');
                 return;
            }
            // Verify current password matches the one used for the session
            if (currentPassword !== adminPassword) {
                 showChangePasswordError('当前密码不正确。');
                 return;
            }


            const result = await apiCall('/auth/change-password', 'POST', { currentPassword, newPassword });
            if (result && result.success) {
                showChangePasswordSuccess('密码修改成功！请使用新密码重新登录。');
                adminPassword = newPassword; // Update session password
                localStorage.setItem('cloudrouter_admin_password', newPassword); // Update stored password
                changePasswordForm.reset();
                // Optionally force re-login: logoutButton.click();
            }
             // Error handled by apiCall
        });


        // --- Initial Load ---
        document.addEventListener('DOMContentLoaded', checkAuthStatus);

    </script>
</body>
</html>`;
    }
    return new Response(adminHtmlContent, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}


// --- API 路由 ---

// --- 管理员认证 API ---
router.get('/api/admin/auth/status', async (request, env) => {
  await initializeState(env); //确保状态已加载
  return new Response(JSON.stringify({ isPasswordSet: !!adminPasswordHash }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

router.post('/api/admin/auth/setup', async (request, env) => {
  await initializeState(env);
  if (adminPasswordHash) {
    return new Response(JSON.stringify({ error: '密码已设置' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const { password } = await request.json();
    if (!password || password.length < 8) {
      return new Response(JSON.stringify({ error: '密码无效或太短（至少8位）' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    const newHash = await hashPassword(password);
    await env.ROUTER_KV.put(KV_KEYS.ADMIN_PASSWORD_HASH, newHash);
    adminPasswordHash = newHash; // 更新缓存

    return new Response(JSON.stringify({ success: true, message: '管理员密码设置成功' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("密码设置失败:", error);
    return new Response(JSON.stringify({ error: '设置密码时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});

router.post('/api/admin/auth/login', async (request, env) => {
  await initializeState(env);
  if (!adminPasswordHash) {
    return new Response(JSON.stringify({ error: '管理员密码尚未设置' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const { password } = await request.json();
    const isValid = await verifyPassword(password, adminPasswordHash);

    if (isValid) {
      return new Response(JSON.stringify({ success: true, message: '登录成功' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } else {
      return new Response(JSON.stringify({ error: '密码错误' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
  } catch (error) {
     console.error("登录失败:", error);
     return new Response(JSON.stringify({ error: '登录时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});

router.post('/api/admin/auth/change-password', requireAdminAuth, async (request, env) => {
  // requireAdminAuth 已经验证了当前密码 (存储在 request.adminPassword)
  try {
    const { newPassword } = await request.json();

    if (!newPassword || newPassword.length < 8) {
      return new Response(JSON.stringify({ error: '新密码无效或太短（至少8位）' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // 验证 request.adminPassword (旧密码) 是否真的匹配当前哈希，双重检查
     const isOldPasswordValid = await verifyPassword(request.adminPassword, adminPasswordHash);
     if (!isOldPasswordValid) {
         // 这理论上不应该发生，因为 requireAdminAuth 已经检查过了
         console.error("Change password security check failed: request.adminPassword mismatch.");
         return new Response(JSON.stringify({ error: '当前密码验证失败' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
     }


    const newHash = await hashPassword(newPassword);
    await env.ROUTER_KV.put(KV_KEYS.ADMIN_PASSWORD_HASH, newHash);
    adminPasswordHash = newHash; // 更新缓存

    return new Response(JSON.stringify({ success: true, message: '密码修改成功' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("密码修改失败:", error);
    return new Response(JSON.stringify({ error: '修改密码时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});


// --- 管理员 API 密钥管理 ---
router.get('/api/admin/keys', requireAdminAuth, async (request, env) => {
  // requireAdminAuth 确保了认证
  // 状态已经在初始化或健康检查时加载/更新
  // 返回缓存的密钥列表及其健康状态
  return new Response(JSON.stringify({ success: true, keys: apiKeys.map(k => ({ name: k.name, isHealthy: k.isHealthy })) }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

router.post('/api/admin/keys', requireAdminAuth, async (request, env) => {
  try {
    const { name, value } = await request.json();
    if (!name || !value || !value.startsWith('sk-')) { // OpenRouter keys usually start with sk-
      return new Response(JSON.stringify({ error: '无效的密钥名称或值' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    // 检查名称是否重复
    if (apiKeys.some(key => key.name === name)) {
       return new Response(JSON.stringify({ error: '已存在同名密钥' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
    }

    const newKey = { name, value, isHealthy: null }; // 初始状态未知
    apiKeys.push(newKey);

    // 立即检查新密钥的健康状态（可选，但推荐）
    newKey.isHealthy = await checkKeyHealth(newKey);

    await env.ROUTER_KV.put(KV_KEYS.API_KEYS, JSON.stringify(apiKeys));

    return new Response(JSON.stringify({ success: true, message: '密钥添加成功', key: { name: newKey.name, isHealthy: newKey.isHealthy } }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error("添加密钥失败:", error);
    return new Response(JSON.stringify({ error: '添加密钥时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});

router.delete('/api/admin/keys/:name', requireAdminAuth, async (request, env) => {
  try {
    const nameToDelete = decodeURIComponent(request.params.name);
    const initialLength = apiKeys.length;
    apiKeys = apiKeys.filter(key => key.name !== nameToDelete);

    if (apiKeys.length < initialLength) {
      await env.ROUTER_KV.put(KV_KEYS.API_KEYS, JSON.stringify(apiKeys));
      return new Response(JSON.stringify({ success: true, message: '密钥删除成功' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
       // 或者返回 204 No Content
       // return new Response(null, { status: 204 });
    } else {
      return new Response(JSON.stringify({ error: '未找到指定名称的密钥' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
    }
  } catch (error) {
    console.error("删除密钥失败:", error);
    return new Response(JSON.stringify({ error: '删除密钥时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});


// --- OpenAI 兼容 API 路由 ---
router.post('/v1/chat/completions', async (request, env) => {
  // 使用简化的访问验证
  if (!validateApiAccess(request, env)) {
    return new Response(JSON.stringify({ error: '未授权或无效的 API 密钥格式' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // 确保状态已初始化
  // await initializeState(env); // 通常在 fetch handler 中调用一次即可

  // 执行健康检查（如果需要）
  await healthCheck(); // healthCheck 内部有频率控制

  const key = getNextKey();
  if (!key) {
    return new Response(JSON.stringify({ error: '当前没有可用的 OpenRouter API 密钥' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const requestBody = await request.text(); // 读取原始请求体

    // 转发请求到 OpenRouter
    const response = await fetch(`${OPENROUTER_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${key.value}`,
        'HTTP-Referer': request.headers.get('Referer') || 'https://cloudrouter.project', // 尝试传递原始 Referer
        'X-Title': 'CloudRouter',
        // 传递其他可能相关的头信息？
      },
      body: requestBody // 直接转发原始请求体
    });

    // 检查 OpenRouter 的响应状态
    if (!response.ok) {
        console.error(`OpenRouter 请求失败 (密钥: ${key.name}): ${response.status} ${response.statusText}`);
        // 如果是认证错误 (401) 或限流 (429)，标记密钥为不健康
        if (response.status === 401 || response.status === 429) {
            const keyIndex = apiKeys.findIndex(k => k.name === key.name);
            if (keyIndex !== -1) {
                apiKeys[keyIndex].isHealthy = false;
                // 可以在这里触发一次 KV 更新，但会增加写入次数
                // await env.ROUTER_KV.put(KV_KEYS.API_KEYS, JSON.stringify(apiKeys));
            }
        }
        // 将 OpenRouter 的错误响应直接透传给客户端
        return new Response(response.body, {
            status: response.status,
            headers: { 'Content-Type': 'application/json' } // 假设 OpenRouter 返回 JSON 错误
        });
    }


    // 流式响应处理
    if (response.headers.get('content-type')?.includes('text/event-stream')) {
        return new Response(response.body, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
            }
        });
    } else {
        // 非流式响应
        const data = await response.json();
        return new Response(JSON.stringify(data), {
            headers: { 'Content-Type': 'application/json' }
        });
    }

  } catch (error) {
    console.error('处理 /v1/chat/completions 请求失败:', error);
    // 标记当前使用的密钥为不健康
    if (key) {
       const keyIndex = apiKeys.findIndex(k => k.name === key.name);
       if (keyIndex !== -1) {
           apiKeys[keyIndex].isHealthy = false;
       }
    }
    return new Response(JSON.stringify({ error: '处理请求时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});

router.get('/v1/models', async (request, env) => {
  if (!validateApiAccess(request, env)) {
    return new Response(JSON.stringify({ error: '未授权或无效的 API 密钥格式' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
  }

  // await initializeState(env); // 确保状态已初始化
  await healthCheck(); // 执行健康检查

  const key = getNextKey();
  if (!key) {
    return new Response(JSON.stringify({ error: '当前没有可用的 OpenRouter API 密钥' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  }

  try {
    const response = await fetch(`${OPENROUTER_BASE_URL}/models`, {
      headers: {
        'Authorization': `Bearer ${key.value}`,
        'HTTP-Referer': 'https://cloudrouter.project',
        'X-Title': 'CloudRouter'
      }
    });

     if (!response.ok) {
        console.error(`获取模型列表失败 (密钥: ${key.name}): ${response.status} ${response.statusText}`);
         if (response.status === 401 || response.status === 429) {
             const keyIndex = apiKeys.findIndex(k => k.name === key.name);
             if (keyIndex !== -1) apiKeys[keyIndex].isHealthy = false;
         }
        return new Response(response.body, {
            status: response.status,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const data = await response.json();

    // 转换为 OpenAI 格式 (如果需要，OpenRouter 的格式可能已经兼容)
    // const openaiFormatModels = data.data.map(model => ({
    //   id: model.id,
    //   object: "model",
    //   created: Date.parse(model.created_at || new Date().toISOString()) / 1000, // 尝试解析创建时间
    //   owned_by: model.owned_by?.id || "openrouter",
    // }));

    return new Response(JSON.stringify(data), { // 直接返回 OpenRouter 的响应
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('获取 /v1/models 失败:', error);
     if (key) {
       const keyIndex = apiKeys.findIndex(k => k.name === key.name);
       if (keyIndex !== -1) apiKeys[keyIndex].isHealthy = false;
     }
    return new Response(JSON.stringify({ error: '获取模型列表时发生内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
});

// --- 前端和 404 ---
// 根路径提供管理界面
router.get('/', async (request, env) => {
    return getAdminHtml(env);
});

// 捕获所有其他路由作为 404
router.all('*', () => new Response('404 Not Found', { status: 404 }));


// --- Worker 入口 ---
export default {
  async fetch(request, env, ctx) {
    // 在每次请求开始时初始化状态（KV 读取有缓存，开销不大）
    // 或者考虑使用 Durable Objects 来管理状态，但这会增加复杂性
    await initializeState(env);

    // 异步执行健康检查，不阻塞请求处理
    // ctx.waitUntil(healthCheck()); // 在非计划的 fetch 中可能不可靠，改为在 API 调用前检查

    return router.handle(request, env, ctx);
  },

  // 定时任务，用于定期健康检查 (如果配置了 cron 触发器)
  // async scheduled(event, env, ctx) {
  //   ctx.waitUntil(initializeState(env).then(() => healthCheck()));
  // }
};
