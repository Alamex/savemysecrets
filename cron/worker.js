// Daily trigger for Save My Secrets check-ins. Calls the site's escalation endpoint.
export default {
  async scheduled(event, env, ctx) {
    const r = await fetch('https://savemysecrets.com/api/admin/run-escalation', {
      method: 'POST', headers: { authorization: `Bearer ${env.ADMIN_TOKEN}`, 'content-type': 'application/json' }, body: '{}' });
    console.log('escalation', r.status, await r.text());
  },
  async fetch() { return new Response('savemysecrets-cron', { status: 200 }); },
};
