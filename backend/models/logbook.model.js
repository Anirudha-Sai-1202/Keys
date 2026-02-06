import mongoose from "mongoose";

const logbookSchema = new mongoose.Schema(
  {
    keyNumber: {
      type: String,
      required: true,
      trim: true,
    },
    keyName: {
      type: String,
      required: true,
      trim: true,
    },
    location: {
      type: String,
      required: true,
      trim: true,
    },
    status: {
      type: String,
      enum: ["available", "unavailable"],
      default: "available",
    },
    takenBy: {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null,
      },
      name: {
        type: String,
        default: null,
      },
      email: {
        type: String,
        default: null,
      },
    },
    takenAt: {
      type: Date,
      default: null,
    },
    returnedBy: {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null,
      },
      name: {
        type: String,
        default: null,
      },
      email: {
        type: String,
        default: null,
      },
    },
    returnedAt: {
      type: Date,
      default: null,
    },
    frequentlyUsed: {
      type: Boolean,
      default: false,
    },
    description: {
      type: String,
      trim: true,
      default: "",
    },
    category: {
      type: String,
      enum: ["classroom", "lab", "office", "storage", "library", "auditorium", "cafeteria", "hostel", "maintenance", "security", "staffroom", "other"],
      default: "other",
    },
    department: {
      type: String,
      enum: [
        "Accounts",
        "Admission",
        "Automobile",
        "CAMS",
        "Chemistry",
        "Civil",
        "CSE",
        "CSE-AIML&IOT",
        "CSE-(CyS,DS)_and_AI&DS",
        "Director",
        "EEE",
        "ECE",
        "EIE",
        "English",
        "GRO",
        "HR",
        "Humanity and sciences(H&S)",
        "IQAC",
        "IT",
        "MECH",
        "Other",
        "PAAC",
        "Placement",
        "Principal",
        "Purchase",
        "RCC",
        "SSC",
        "VJ_Hub"
      ],
      default: "Other",
    },
    block: {
      type: String,
      enum: ["A", "B", "C", "D", "E", "F", "G", "H", "PG", "MAIN", "LIB", "AUD", "CAF", "HOSTEL", "OTHER"],
      default: "A",
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    recordedBy: {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      role: {
        type: String,
        enum: ["faculty", "security"],
        required: true,
      }
    }
  },
  {
    timestamps: true,
    collection: "logbook" // Explicitly specify the collection name
  }
);

// Indexes for better performance
logbookSchema.index({ keyNumber: 1 });
logbookSchema.index({ status: 1 });
logbookSchema.index({ "takenBy.userId": 1 });
logbookSchema.index({ department: 1 });
logbookSchema.index({ block: 1 });
logbookSchema.index({ "recordedBy.userId": 1 });
logbookSchema.index({ "recordedBy.role": 1 });
logbookSchema.index({ createdAt: 1 }); // For chronological queries

// Static method to find records by date range
logbookSchema.statics.findByDateRange = function(startDate, endDate) {
  return this.find({
    createdAt: {
      $gte: startDate,
      $lte: endDate
    }
  });
};

// Static method to find records by recorder (faculty/security)
logbookSchema.statics.findByRecorder = function(userId) {
  return this.find({
    "recordedBy.userId": userId
  });
};

// Static method to find records by department
logbookSchema.statics.findByDepartment = function(department) {
  return this.find({ department });
};

export const Logbook = mongoose.model("Logbook", logbookSchema);