export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Proxy all /api/* requests to AWS EC2 backend
    if (url.pathname.startsWith('/api/')) {
      const backendUrl = new URL(url.pathname + url.search, 'http://13.234.121.199:8080');
      const modifiedRequest = new Request(backendUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow',
      });

      try {
        const response = await fetch(modifiedRequest);
        const headers = new Headers(response.headers);
        headers.set('Access-Control-Allow-Origin', '*');
        headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers,
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Backend unreachable', details: String(err) }), {
          status: 502,
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        });
      }
    }

    // Serve static assets with automatic Single-Page Application fallback
    return env.ASSETS.fetch(request);
  },
};
