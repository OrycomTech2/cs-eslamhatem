// routes/stats.js
const express = require('express');
const router = express.Router();
const Course = require('../models/Course');
const Content = require('../models/Content');

router.get('/', async (req, res) => {
  try {
    // Use aggregation that doesn't require ObjectId conversion
    const stats = await Content.aggregate([
      {
        $group: {
          _id: null,  // Group all documents together
          activeCourses: { $sum: 1 },
          videoLessons: {
            $sum: {
              $cond: [
                { $ifNull: ["$video", false] },
                1,
                0
              ]
            }
          },
          pdfResources: {
            $sum: {
              $cond: [
                { $ifNull: ["$pdf", false] },
                1,
                0
              ]
            }
          }
        }
      }
    ]);

    // Extract results or use defaults
    const result = stats[0] || {
      activeCourses: 0,
      videoLessons: 0,
      pdfResources: 0
    };

    res.json({
      success: true,
      data: result
    });

  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({
      success: false,
      error: 'Failed to load statistics'
    });
  }
});

module.exports = router;