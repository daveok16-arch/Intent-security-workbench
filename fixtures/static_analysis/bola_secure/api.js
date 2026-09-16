// Secure Authorization Implementation (JavaScript/Express)
// Direct object reference protected by explicit ownership and permission verification

const express = require('express');
const router = express.Router();
const db = require('./database');

// GET /api/v1/documents/:id
// SECURE: Validates that requester owns the resource or has permission
router.get('/documents/:id', async (req, res) => {
  const documentId = req.params.id;
  const doc = await db.documents.findOne({ _id: documentId });

  if (!doc) {
    return res.status(404).json({ error: 'Document not found' });
  }

  // Explicit ownership validation
  if (doc.ownerId !== req.user.id && !req.user.roles.includes('ADMIN')) {
    return res.status(403).json({ error: 'Access denied: forbidden resource access' });
  }

  return res.json(doc);
});

// DELETE /api/v1/orders/:id
// SECURE: Query scoped strictly to the authenticated tenant/user
router.delete('/orders/:id', async (req, res) => {
  const orderId = req.params.id;
  const currentUserId = req.user.id;

  const result = await db.orders.deleteOne({
    id: orderId,
    userId: currentUserId, // Scoped deletion prevents tampering with other users' records
  });

  if (result.deletedCount === 0) {
    return res.status(404).json({ error: 'Order not found or unauthorized' });
  }

  return res.json({ success: true });
});

module.exports = router;
