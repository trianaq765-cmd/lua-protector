# Via curl (ganti ADMIN_SECRET dengan yang ada di server)
curl -X POST https://your-server.com/api/admin/unblock \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"ip": "YOUR_IP_ADDRESS"}'

# Unblock semua IP
curl -X POST https://your-server.com/api/admin/unblock \
  -H "Authorization: Bearer YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"ip": "all"}'