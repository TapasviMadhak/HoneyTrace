// Centralized API Client with automated Auth Header injection
export function getAuthHeaders(): Record<string, string> {
  const storedKey = typeof window !== 'undefined' ? localStorage.getItem('honeytrace_api_key') : null;
  const envKey = import.meta.env.VITE_HONEYTRACE_API_KEY || '';
  const key = (storedKey || envKey || '').trim();

  if (!key) {
    return {};
  }

  return {
    'X-API-Key': key,
  };
}

export async function secureFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const headers = {
    ...getAuthHeaders(),
    ...(options.headers || {}),
  };

  return fetch(url, {
    ...options,
    headers,
  });
}
