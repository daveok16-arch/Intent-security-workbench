// Vulnerable BOLA Endpoint (JavaScript/Express)
// Direct object reference using client-provided id without ownership validation

const express = require('express');
const router = express.Router();
const db = require('./database');

// GET /api/v1/documents/:id
// VULNERABLE: Direct access to document by ID without verifying current user owns it
router.get('/documents/:id', async (req, res) => {
  const documentId = req.params.id;
  const doc = await db.documents.findOne({ _id: documentId });
  
  if (!doc) {
    return res.status(404).json({ error: 'Document not found' });
  }

  // Missing authorization check: no comparison between doc.ownerId and req.user.id
  return res.json(doc);
});

// DELETE /api/v1/orders/:id
// VULNERABLE: Delete resource solely by route parameter
router.delete('/orders/:id', async (req, res) => {
  const orderId = req.params.id;
  await db.orders.deleteOne({ id: orderId });
  return res.json({ success: true });
});

module.exports = router;
