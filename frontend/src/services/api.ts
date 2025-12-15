import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';

// Define environment variable type
declare const process: {
  env: {
    REACT_APP_API_URL?: string;
  };
};

// API Response Types
interface ApiResponse {
  message?: string;
  error?: string;
  token?: string;
  user?: User;
  user_id?: string;
  email?: string;
  mfa_required?: boolean;
  mfa_session_token?: string;
  requires_mfa?: boolean;
  requiresMFA?: boolean;
  tempToken?: string;
}

export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  mfa_enabled: boolean;
}

export interface LoginResponse {
  token: string;
  user: User;
  mfa_required?: boolean;
  mfa_session_token?: string;
  requiresMFA?: boolean;
  tempToken?: string;
  requires_mfa?: boolean;
}

export interface RegisterResponse {
  token: string;
  user: User;
}

export interface MFAStatus {
  enabled: boolean;
  setup_complete: boolean;
}

export interface MFASetupResponse {
  secret: string;
  qr_code: string;
}

export interface MFAVerifyResponse {
  success: boolean;
  token?: string;
}

// Create axios instance with increased timeout for slow connections
// Use proxy in development (Vite proxies /api to backend) or direct URL
const getBaseURL = () => {
  // In development, use the proxy if available, otherwise use direct URL
  if (import.meta.env.DEV) {
    // Try to use proxy first (works when Vite dev server is running)
    return import.meta.env.VITE_API_URL || '/api';
  }
  // In production, use the configured API URL
  return import.meta.env.VITE_API_URL || 'http://localhost:5002/api';
};

const api = axios.create({
  baseURL: getBaseURL(),
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // Increased from 10000 to 30000 (30 seconds) to handle slow server responses
  withCredentials: true
});

// Auth API endpoints
export const authApi = {
  register: async (data: { email: string; password: string; firstName: string; lastName: string }): Promise<RegisterResponse> => {
    try {
      console.log('[API] Sending registration request:', { ...data, password: '[REDACTED]' });
      
      // Create a specific longer timeout for registration requests
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        controller.abort();
      }, 30000); // 30 second hard timeout
      
      try {
        const response = await api.post<ApiResponse>('/auth/register', data, {
          timeout: 30000, // Timeout for axios
          signal: controller.signal // Abort controller signal
        });
        
        // Clear the timeout since the request completed
        clearTimeout(timeoutId);
        
        console.log('[API] Registration response:', response.data);
        
        // Check if there's an error in the response
        if (response.data.error) {
          console.error('[API] Registration error in response:', response.data.error);
          throw new Error(response.data.error);
        }
        
        if (!response.data.token || !response.data.user) {
          console.error('[API] Invalid response format:', response.data);
          throw new Error('Invalid response format from server. Missing token or user data.');
        }
        
        return {
          token: response.data.token,
          user: response.data.user
        };
      } catch (requestError) {
        // Clear the timeout to prevent memory leaks
        clearTimeout(timeoutId);
        throw requestError;
      }
    } catch (error: any) {
      console.error('[API] Registration error:', error);
      
      // Detect timeout errors specifically
      if (error.name === 'AbortError' || (axios.isAxiosError(error) && error.code === 'ECONNABORTED')) {
        console.error('[API] Registration request timed out');
        throw new Error('Registration request timed out. The server is taking too long to respond. Please try again.');
      } else if (error.name === 'NetworkError' || (axios.isAxiosError(error) && !error.response)) {
        // Check for various network error conditions
        if (axios.isAxiosError(error)) {
          if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
            console.error('[API] Network error - connection refused or network unavailable');
            throw new Error('Cannot connect to server. Please check if the backend server is running and try again.');
          } else if (error.code === 'ETIMEDOUT' || error.message?.includes('timeout')) {
            console.error('[API] Network error - connection timeout');
            throw new Error('Connection timeout. Please check your internet connection and try again.');
          } else {
            console.error('[API] Network error - no internet connection');
            throw new Error('Network error. Please check your internet connection and try again.');
          }
        } else {
          throw new Error('Network error. Please check your internet connection and try again.');
        }
      } else if (axios.isAxiosError(error)) {
        // Handle server response errors
        if (error.response) {
          const errorMessage = error.response.data?.error || error.response.data?.message || `Server error (${error.response.status})`;
          console.error('[API] Error details:', {
            status: error.response.status,
            data: error.response.data,
            message: errorMessage
          });
          throw new Error(errorMessage);
        } else {
          // No response but axios error
          throw new Error(error.message || 'Registration failed. Please try again.');
        }
      }
      // For non-Axios errors, re-throw as-is
      throw error;
    }
  },
  
  login: async (data: { email: string; password: string; mfa_token?: string }): Promise<LoginResponse> => {
    try {
      console.log('[DEBUG API] Sending login request:', { ...data, password: '[REDACTED]' });
      console.time('login-request');
      
      // Create a specific longer timeout for login requests
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        controller.abort();
      }, 30000); // 30 second hard timeout
      
      try {
        const response = await api.post<ApiResponse>('/auth/login', data, {
          timeout: 30000, // Timeout for axios
          signal: controller.signal // Abort controller signal
        });
        
        // Clear the timeout since the request completed
        clearTimeout(timeoutId);
        
        console.timeEnd('login-request');
        console.log('[DEBUG API] Raw login response:', response.data);
        
        // Enhanced check for MFA requirement with different possible field names
        const requiresMFA = response.data.mfa_required || response.data.requires_mfa || response.data.requiresMFA;
        const mfaSessionToken = response.data.mfa_session_token || response.data.tempToken;
        
        // Log MFA detection
        console.log('[DEBUG API] MFA detection result:', { 
          requiresMFA, 
          mfaSessionToken: mfaSessionToken ? '[PRESENT]' : '[MISSING]',
          originalFlags: {
            mfa_required: response.data.mfa_required,
            requires_mfa: response.data.requires_mfa,
            mfa_session_token: response.data.mfa_session_token ? '[PRESENT]' : '[MISSING]'
          }
        });
        
        // Check if MFA is required
        if (requiresMFA) {
          if (!mfaSessionToken) {
            console.error('[DEBUG API] MFA is required but no session token was provided');
            throw new Error('MFA session token not provided by server');
          }
          
          console.log('[DEBUG API] Returning MFA required response');
          return {
            mfa_required: true,
            mfa_session_token: mfaSessionToken,
            requiresMFA: true, // Add explicit flag for frontend consistency
            tempToken: mfaSessionToken, // Add for backwards compatibility
            token: '',
            user: {
              id: response.data.user_id || '',
              email: response.data.email || '',
              firstName: '',
              lastName: '',
              role: '',
              mfa_enabled: true
            }
          };
        }
        
        if (!response.data.token || !response.data.user) {
          console.error('[DEBUG API] Invalid response format from server:', response.data);
          throw new Error('Invalid response format from server');
        }
        
        return {
          token: response.data.token,
          user: response.data.user
        };
      } catch (requestError) {
        // Clear the timeout to prevent memory leaks
        clearTimeout(timeoutId);
        throw requestError;
      }
    } catch (error: any) {
      console.error('[DEBUG API] Login error:', error);
      // Detect timeout errors specifically
      if (error.name === 'AbortError' || (axios.isAxiosError(error) && error.code === 'ECONNABORTED')) {
        console.error('[DEBUG API] Request timed out');
        throw new Error('Login request timed out. The server is taking too long to respond. Please try again.');
      } else if (error.name === 'NetworkError' || (axios.isAxiosError(error) && !error.response)) {
        console.error('[DEBUG API] Network error - no internet connection');
        throw new Error('Network error. Please check your internet connection and try again.');
      } else if (axios.isAxiosError(error)) {
        // Check if the error response indicates MFA is required
        if (error.response?.data?.requires_mfa || error.response?.data?.mfa_required) {
          console.log('[DEBUG API] MFA required from error response');
          return {
            mfa_required: true,
            mfa_session_token: error.response.data.mfa_session_token,
            requiresMFA: true,
            tempToken: error.response.data.mfa_session_token,
            token: '',
            user: {
              id: error.response.data.user_id || '',
              email: error.response.data.email || '',
              firstName: '',
              lastName: '',
              role: '',
              mfa_enabled: true
            }
          };
        }
        
        // Better error handling for specific backend errors
        if (error.response && error.response.status === 401) {
          console.log('[DEBUG API] Authentication error (401):', error.response.data);
          // Make sure we're properly formatting the error object
          const errorMessage = error.response.data.error || error.response.data.message || 'Invalid email or password';
          const err = new Error(errorMessage);
          // Attach the response data for more context
          (err as any).response = { 
            status: error.response.status,
            data: error.response.data 
          };
          throw err;
        }
        
        // Handle other response errors
        if (error.response) {
          console.log(`[DEBUG API] Server error (${error.response.status}):`, error.response.data);
          const errorMessage = error.response.data?.error || error.response.data?.message || `Server error (${error.response.status})`;
          const err = new Error(errorMessage);
          // Attach the response data for more context
          (err as any).response = { 
            status: error.response.status,
            data: error.response.data 
          };
          throw err;
        }
        
        // If no response data, use the error message
        throw new Error(error.message || 'Login failed');
      }
      // For non-Axios errors, use the standard error message
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('An unexpected error occurred during login');
    }
  },
  
  logout: async (): Promise<void> => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        console.warn('No token available for logout');
        return;
      }
      
      console.log('Sending logout request with token');
      await api.post('/auth/logout', {}, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
    } catch (error) {
      console.error('Logout error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Logout failed');
      }
      throw error;
    }
  },
  
  refreshToken: async (): Promise<string> => {
    try {
      const response = await api.post<ApiResponse>('/auth/refresh');
      if (!response.data.token) {
        throw new Error('No token received from server');
      }
      return response.data.token;
    } catch (error) {
      console.error('Token refresh error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Token refresh failed');
      }
      throw error;
    }
  },
  
  getProfile: async (): Promise<User> => {
    try {
      const response = await api.get<ApiResponse>('/auth/me');
      if (!response.data.user) {
        throw new Error('No user data received from server');
      }
      return response.data.user;
    } catch (error) {
      console.error('Get profile error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to fetch profile');
      }
      throw error;
    }
  },

  updateProfile: async (data: { firstName?: string; lastName?: string; email?: string; currentPassword?: string; newPassword?: string }): Promise<User> => {
    try {
      const response = await api.put<ApiResponse>('/auth/profile', data);
      
      if (!response.data.user) {
        throw new Error('No user data received from server');
      }
      
      return response.data.user;
    } catch (error) {
      console.error('Update profile error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to update profile');
      }
      throw error;
    }
  },
  
  deleteAccount: async (data: { password: string }): Promise<{ success: boolean }> => {
    try {
      const response = await api.delete<{ success: boolean }>('/auth/account', {
        data // Send password in request body for DELETE request
      });
      
      return response.data;
    } catch (error) {
      console.error('Delete account error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to delete account');
      }
      throw error;
    }
  },
  
  getAccountActivity: async (): Promise<{ activities: Array<{ date: string; action: string; ip: string; location: string; device: string }> }> => {
    try {
      const response = await api.get<{ activities: Array<{ date: string; action: string; ip: string; location: string; device: string }> }>('/auth/activity');
      return response.data;
    } catch (error) {
      console.error('Get account activity error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to fetch account activity');
      }
      throw error;
    }
  },

  // MFA-related endpoints
  getMFAStatus: async (): Promise<MFAStatus> => {
    try {
      const response = await api.get<MFAStatus>('/mfa/status');
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to get MFA status');
      }
      throw new Error('Network error while getting MFA status');
    }
  },

  // Add token validation and refresh logic
  validateAndRefreshToken: async (): Promise<void> => {
    const token = localStorage.getItem('token');
    if (!token) {
      throw new Error('User is not logged in');
    }

    const tokenExpiry = localStorage.getItem('token_expiry');
    if (tokenExpiry && new Date(tokenExpiry) < new Date()) {
      console.log('Token expired, refreshing...');
      const newToken = await authApi.refreshToken();
      localStorage.setItem('token', newToken);
      localStorage.setItem('token_expiry', new Date(Date.now() + 3600 * 1000).toISOString()); // Assuming 1-hour expiry
    }
  },

  // Ensure token is valid before calling setupMFA
  setupMFA: async (): Promise<MFASetupResponse> => {
    try {
      console.log('Starting setupMFA API call...');
      
      // Get user ID and token from localStorage
      const userId = localStorage.getItem('user_id');
      const token = localStorage.getItem('token');
      
      if (!userId || !token) {
        console.error('Missing user_id or token in localStorage');
        throw new Error('Authentication data missing');
      }
      
      // Use the new endpoint specifically designed for newly registered users
      const response = await api.post<MFASetupResponse>('/mfa/setup-for-new-user', {
        user_id: userId,
        token: token
      });
      
      console.log('setupMFA API response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error during setupMFA API call:', error);
      if (axios.isAxiosError(error)) {
        console.error('Axios error details:', error.response?.data);
        throw new Error(error.response?.data?.error || 'Failed to setup MFA');
      }
      throw new Error('Network error while setting up MFA');
    }
  },

  verifyMFA: async (data: { mfa_session_token: string; token: string }): Promise<MFAVerifyResponse> => {
    try {
      console.log('Verifying MFA with session token:', data.mfa_session_token);
      const response = await api.post<any>('/auth/verify-mfa', data);
      
      console.log('MFA verification response:', response.data);
      
      if (!response.data.token) {
        throw new Error('No authentication token received after MFA verification');
      }
      
      return {
        success: true,
        token: response.data.token
      };
    } catch (error) {
      console.error('MFA verification error:', error);
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to verify MFA');
      }
      throw new Error('Network error while verifying MFA');
    }
  },

  disableMFA: async (data: { password: string }): Promise<{ success: boolean }> => {
    try {
      const response = await api.post<{ success: boolean }>('/mfa/disable', data);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to disable MFA');
      }
      throw new Error('Network error while disabling MFA');
    }
  },

  generateBackupCodes: async (data: { password: string }): Promise<{ backup_codes: string[] }> => {
    try {
      const response = await api.post<{ backup_codes: string[] }>('/mfa/generate-backup-codes', data);
      return response.data;
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(error.response?.data?.error || 'Failed to generate backup codes');
      }
      throw new Error('Network error while generating backup codes');
    }
  }
};

// Fix the key name to use 'token' consistently across the application
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
      console.log('Authorization header set:', `Bearer ${token.substring(0, 10)}...`);
    } else {
      console.warn('No token found in localStorage');
    }
    
    // Add MFA token if available
    const mfaToken = localStorage.getItem('mfa_token');
    if (mfaToken) {
      config.headers['X-MFA-TOKEN'] = mfaToken;
      console.log('X-MFA-TOKEN header set for request');
    } else if (window.location.pathname.includes('/verify')) {
      console.warn('No MFA token found for verification page');
    }
    
    console.log('Request:', {
      url: config.url,
      method: config.method,
      headers: {
        ...config.headers,
        Authorization: config.headers.Authorization ? 'Bearer [REDACTED]' : 'None',
        'X-MFA-TOKEN': mfaToken ? '[PRESENT]' : '[ABSENT]'
      }
    });
    return config;
  },
  (error) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// Add response interceptor to handle token refresh
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (token: string) => void;
  reject: (error: Error) => void;
}> = [];

const processQueue = (error: Error | null, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else if (token) {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => {
    console.log('Response:', {
      url: response.config.url,
      status: response.status,
      data: response.data
    });
    return response;
  },
  async (error) => {
    console.error('Response error:', error);
    
    // Handle network errors before checking for 401
    if (axios.isAxiosError(error) && !error.response) {
      // Network error - no response from server
      if (error.code === 'ECONNREFUSED' || error.code === 'ERR_NETWORK') {
        console.error('[Interceptor] Connection refused or network unavailable');
        return Promise.reject(new Error('Cannot connect to server. Please check if the backend server is running.'));
      } else if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
        console.error('[Interceptor] Request timeout');
        return Promise.reject(new Error('Request timed out. Please try again.'));
      } else {
        console.error('[Interceptor] Network error:', error.message);
        return Promise.reject(new Error('Network error. Please check your internet connection.'));
      }
    }
    
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        try {
          const token = await new Promise<string>((resolve, reject) => {
            failedQueue.push({ resolve, reject });
          });
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        } catch (err) {
          return Promise.reject(err);
        }
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const token = await authApi.refreshToken();
        localStorage.setItem('token', token);
        originalRequest.headers.Authorization = `Bearer ${token}`;
        processQueue(null, token);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError as Error);
        localStorage.removeItem('token');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;