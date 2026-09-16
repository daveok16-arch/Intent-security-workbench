// Routes file
app.get('/orders', async (req, res) => {
  const orders = await db.orders.find();
  res.json(orders);
});

// Vulnerable to BOLA: accepts orderId, has role check, but NO ownership check!
app.delete('/orders/:orderId', async (req, res) => {
  const user = req.user;
  if (!user.roles.includes('user')) {
    return res.status(403).send('Forbidden');
  }
  // Missing: user.id === order.owner_id
  const order = await db.orders.findById(req.params.orderId);
  await order.delete();
  res.status(204).send();
});

// Secure endpoint: explicitly enforces caller == owner
app.put('/users/:userId/documents/:documentId', async (req, res) => {
  const caller = req.user;
  const doc = await db.docs.findById(req.params.documentId);
  if (caller.id !== doc.owner_id) {
    return res.status(403).send('Forbidden');
  }
  await doc.update(req.body);
  res.json(doc);
});

// Shadow API: Exists in source code but NOT in OpenAPI spec!
app.post('/internal/admin/purge-cache', async (req, res) => {
  await cache.flush();
  res.json({ ok: true });
});