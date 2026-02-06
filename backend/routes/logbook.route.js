import express from 'express';
import { verifyToken } from '../middleware/verifyToken.js';
import { requireRole } from '../middleware/roleAuth.js';
import {
  createLogbookEntry,
  getLogbookEntries,
  getLogbookStats,
  getAdminLogbookEntries
} from '../controllers/logbook.controller.js';

const router = express.Router();

// Protected routes - require authentication
router.use(verifyToken);

// Route to create a logbook entry - accessible by faculty and security
router.post(
  '/entries',
  requireRole('faculty', 'security'),
  createLogbookEntry
);

// Route to get logbook entries - accessible by security
router.get(
  '/entries',
  requireRole('security'),
  getLogbookEntries
);

// Admin-specific routes
// Route to get detailed logbook entries with advanced filtering and pagination
router.get(
  '/admin/entries',
  requireRole('admin'),
  getAdminLogbookEntries
);

// Route to get logbook statistics - accessible by admin only
router.get(
  '/stats',
  requireRole('admin'),
  getLogbookStats
);

export default router;