// Security headers configuration and utilities
export interface SecurityHeaders {
  'Content-Security-Policy'?: string;
  'X-Frame-Options'?: string;
  'X-Content-Type-Options'?: string;
  'X-XSS-Protection'?: string;
  'Referrer-Policy'?: string;
  'Permissions-Policy'?: string;
  'Strict-Transport-Security'?: string;
}

export class SecurityHeadersManager {
  private static readonly DEFAULT_CSP = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://kzutwcexyafwggfkwquq.supabase.co",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    "media-src 'self' https:",
    "connect-src 'self' https://kzutwcexyafwggfkwquq.supabase.co wss://kzutwcexyafwggfkwquq.supabase.co",
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; ');

  static getSecurityHeaders(): SecurityHeaders {
    return {
      'Content-Security-Policy': this.DEFAULT_CSP,
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': [
        'camera=()',
        'microphone=()',
        'geolocation=()',
        'payment=()',
        'usb=()',
        'magnetometer=()',
        'accelerometer=()',
        'gyroscope=()'
      ].join(', '),
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
    };
  }

  static applyClientSideSecurityMeasures(): void {
    try {
      // Disable right-click context menu in production
      if (process.env.NODE_ENV === 'production') {
        document.addEventListener('contextmenu', (e) => {
          e.preventDefault();
          return false;
        });

        // Disable F12, Ctrl+Shift+I, Ctrl+U
        document.addEventListener('keydown', (e) => {
          if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && e.key === 'I') ||
            (e.ctrlKey && e.key === 'U')
          ) {
            e.preventDefault();
            return false;
          }
        });
      }

      // Set secure cookie attributes
      this.setSecureCookieDefaults();

      // Monitor for console tampering
      this.setupConsoleProtection();

    } catch (error) {
      console.warn('Failed to apply client-side security measures:', error);
    }
  }

  private static setSecureCookieDefaults(): void {
    // Override document.cookie to enforce secure attributes
    const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    
    if (originalCookieDescriptor) {
      Object.defineProperty(document, 'cookie', {
        get() {
          return originalCookieDescriptor.get?.call(this);
        },
        set(value: string) {
          // Ensure cookies have secure attributes in production
          if (process.env.NODE_ENV === 'production' && location.protocol === 'https:') {
            if (!value.includes('Secure')) {
              value += '; Secure';
            }
            if (!value.includes('SameSite')) {
              value += '; SameSite=Strict';
            }
          }
          return originalCookieDescriptor.set?.call(this, value);
        },
        configurable: true
      });
    }
  }

  private static setupConsoleProtection(): void {
    if (process.env.NODE_ENV === 'production') {
      // Detect console usage
      let devtools = false;
      const threshold = 160;

      const detectDevTools = () => {
        if (window.outerHeight - window.innerHeight > threshold || 
            window.outerWidth - window.innerWidth > threshold) {
          if (!devtools) {
            devtools = true;
            console.clear();
            console.log(
              '%cSecurity Notice',
              'color: red; font-size: 50px; font-weight: bold;'
            );
            console.log(
              '%cThis is a browser feature intended for developers. Unauthorized access or tampering may violate security policies.',
              'color: red; font-size: 16px;'
            );
          }
        } else {
          devtools = false;
        }
      };

      // Check periodically
      setInterval(detectDevTools, 500);
    }
  }

  static sanitizeUrl(url: string): string {
    try {
      const parsedUrl = new URL(url);
      
      // Only allow specific protocols
      const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
      if (!allowedProtocols.includes(parsedUrl.protocol)) {
        throw new Error('Invalid protocol');
      }

      // Remove dangerous URL components
      parsedUrl.username = '';
      parsedUrl.password = '';

      return parsedUrl.toString();
    } catch (error) {
      // Return safe fallback for invalid URLs
      return '#';
    }
  }

  static validateFileUpload(file: File): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check file size (10MB limit)
    const maxSize = 10 * 1024 * 1024;
    if (file.size > maxSize) {
      errors.push('File size exceeds 10MB limit');
    }

    // Validate file type
    const allowedTypes = [
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/pdf',
      'text/plain',
      'application/json'
    ];

    if (!allowedTypes.includes(file.type)) {
      errors.push('File type not allowed');
    }

    // Validate file extension
    const allowedExtensions = ['.csv', '.xlsx', '.xls', '.pdf', '.txt', '.json'];
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!allowedExtensions.includes(fileExtension)) {
      errors.push('File extension not allowed');
    }

    // Check for potential malicious file names
    const dangerousPatterns = [
      /\.(exe|bat|cmd|scr|pif|com|jar|vbs|js|jar)$/i,
      /[<>:"|?*]/,
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)/i
    ];

    if (dangerousPatterns.some(pattern => pattern.test(file.name))) {
      errors.push('File name contains invalid characters or patterns');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  static createSecureFormData(data: Record<string, any>): FormData {
    const formData = new FormData();
    
    for (const [key, value] of Object.entries(data)) {
      // Validate key names
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
        throw new Error(`Invalid form field name: ${key}`);
      }

      // Sanitize values
      if (typeof value === 'string') {
        formData.append(key, value.trim());
      } else if (value instanceof File) {
        const validation = this.validateFileUpload(value);
        if (!validation.isValid) {
          throw new Error(`File validation failed: ${validation.errors.join(', ')}`);
        }
        formData.append(key, value);
      } else {
        formData.append(key, String(value));
      }
    }

    return formData;
  }

  static logSecurityEvent(eventType: string, details: any): void {
    // Log security-related events for monitoring
    const securityEvent = {
      type: eventType,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      details: details
    };

    // In production, this should be sent to a security monitoring service
    if (process.env.NODE_ENV === 'development') {
      console.log('Security Event:', securityEvent);
    }

    // Store locally for debugging (limit to last 100 events)
    try {
      const events = JSON.parse(localStorage.getItem('security_events') || '[]');
      events.unshift(securityEvent);
      localStorage.setItem('security_events', JSON.stringify(events.slice(0, 100)));
    } catch (error) {
      // Ignore localStorage errors
    }
  }
}

// Initialize security measures when module loads
if (typeof window !== 'undefined') {
  SecurityHeadersManager.applyClientSideSecurityMeasures();
}