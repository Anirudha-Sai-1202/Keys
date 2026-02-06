import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { X, Save, Plus } from 'lucide-react';

const KeyForm = ({ 
  isOpen, 
  onClose, 
  onSubmit, 
  initialData = null, 
  isLoading = false,
  title = "Add New Key" 
}) => {
  const [formData, setFormData] = useState({
    keyNumber: '',
    keyName: '',
    location: '',
    description: '',
    category: '',
    block: '',
    department: '',
    frequentlyUsed: false
  });

  const [errors, setErrors] = useState({});

  // Categories for dropdown - matching backend schema
  const categories = [
    { value: 'classroom', label: 'Classroom' },
    { value: 'lab', label: 'Lab' },
    { value: 'office', label: 'Office' },
    { value: 'storage', label: 'Storage' },
    { value: 'library', label: 'Library' },
    { value: 'auditorium', label: 'Auditorium' },
    { value: 'cafeteria', label: 'Cafeteria' },
    { value: 'hostel', label: 'Hostel' },
    { value: 'maintenance', label: 'Maintenance' },
    { value: 'security', label: 'Security' },
    { value: 'staffroom', label: 'Staffroom' },
    { value: 'other', label: 'Other' }
  ];

  // Blocks for dropdown - matching backend schema
  const blocks = [
    { value: 'A', label: 'A Block' },
    { value: 'B', label: 'B Block' },
    { value: 'C', label: 'C Block' },
    { value: 'D', label: 'D Block' },
    { value: 'E', label: 'E Block' },
    { value: 'F', label: 'F Block' },
    { value: 'G', label: 'G Block' },
    { value: 'H', label: 'H Block' },
    { value: 'PG', label: 'PG Block' },
    { value: 'MAIN', label: 'Main Building' },
    { value: 'LIB', label: 'Library' },
    { value: 'AUD', label: 'Auditorium' },
    { value: 'CAF', label: 'Cafeteria' },
    { value: 'HOSTEL', label: 'Hostel' },
    { value: 'OTHER', label: 'Other' }
  ];

  // Departments for dropdown - matching backend schema
  const departments = [
    { value: 'Accounts', label: 'Accounts' },
    { value: 'Admission', label: 'Admission' },
    { value: 'Automobile', label: 'Automobile' },
    { value: 'CAMS', label: 'CAMS' },
    { value: 'Chemistry', label: 'Chemistry' },
    { value: 'Civil', label: 'Civil' },
    { value: 'CSE', label: 'CSE' },
    { value: 'CSE-AIML&IOT', label: 'CSE-AIML&IOT' },
    { value: 'CSE-(CyS,DS)_and_AI&DS', label: 'CSE-(CyS,DS)_and_AI&DS' },
    { value: 'Director', label: 'Director' },
    { value: 'EEE', label: 'EEE' },
    { value: 'ECE', label: 'ECE' },
    { value: 'EIE', label: 'EIE' },
    { value: 'English', label: 'English' },
    { value: 'GRO', label: 'GRO' },
    { value: 'HR', label: 'HR' },
    { value: 'Humanity and sciences(H&S)', label: 'Humanity and sciences(H&S)' },
    { value: 'IQAC', label: 'IQAC' },
    { value: 'IT', label: 'IT' },
    { value: 'MECH', label: 'MECH' },
    { value: 'Other', label: 'Other' },
    { value: 'PAAC', label: 'PAAC' },
    { value: 'Placement', label: 'Placement' },
    { value: 'Principal', label: 'Principal' },
    { value: 'Purchase', label: 'Purchase' },
    { value: 'RCC', label: 'RCC' },
    { value: 'SSC', label: 'SSC' },
    { value: 'VJ_Hub', label: 'VJ_Hub' }
  ];

  useEffect(() => {
    if (initialData) {
      setFormData({
        keyNumber: initialData.keyNumber || '',
        keyName: initialData.keyName || '',
        location: initialData.location || '',
        description: initialData.description || '',
        category: initialData.category || '',
        block: initialData.block || '',
        department: initialData.department || 'Other',
        frequentlyUsed: initialData.frequentlyUsed || false
      });
    } else {
      setFormData({
        keyNumber: '',
        keyName: '',
        location: '',
        description: '',
        category: '',
        block: '',
        department: 'Other',
        frequentlyUsed: false
      });
    }
    setErrors({});
  }, [initialData, isOpen]);

  const validateForm = () => {
    const newErrors = {};

    if (!formData.keyNumber.trim()) {
      newErrors.keyNumber = 'Key number is required';
    }

    if (!formData.keyName.trim()) {
      newErrors.keyName = 'Key name is required';
    }

    if (!formData.location.trim()) {
      newErrors.location = 'Location is required';
    }

    if (!formData.category) {
      newErrors.category = 'Category is required';
    }

    if (!formData.block) {
      newErrors.block = 'Block is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    // Prevent multiple submissions
    if (isLoading) {
      return;
    }

    if (!validateForm()) {
      return;
    }

    onSubmit(formData);
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));

    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: ''
      }));
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.9 }}
        className="bg-gray-900 rounded-xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto border border-gray-700"
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            {initialData ? <Save className="w-6 h-6" /> : <Plus className="w-6 h-6" />}
            {title}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-6 h-6" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Key Number */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Key Number *
            </label>
            <input
              type="text"
              value={formData.keyNumber}
              onChange={(e) => handleInputChange('keyNumber', e.target.value)}
              className={`w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.keyNumber ? 'border-red-500' : 'border-gray-600'
              }`}
              placeholder="e.g., CSE-101, LAB-A-01"
              disabled={isLoading}
            />
            {errors.keyNumber && (
              <p className="text-red-400 text-sm mt-1">{errors.keyNumber}</p>
            )}
          </div>

          {/* Key Name */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Key Name *
            </label>
            <input
              type="text"
              value={formData.keyName}
              onChange={(e) => handleInputChange('keyName', e.target.value)}
              className={`w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.keyName ? 'border-red-500' : 'border-gray-600'
              }`}
              placeholder="e.g., Computer Lab 1, Faculty Room"
              disabled={isLoading}
            />
            {errors.keyName && (
              <p className="text-red-400 text-sm mt-1">{errors.keyName}</p>
            )}
          </div>

          {/* Location */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Location *
            </label>
            <input
              type="text"
              value={formData.location}
              onChange={(e) => handleInputChange('location', e.target.value)}
              className={`w-full px-4 py-2 bg-gray-800 border rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                errors.location ? 'border-red-500' : 'border-gray-600'
              }`}
              placeholder="e.g., Ground Floor, Room 101"
              disabled={isLoading}
            />
            {errors.location && (
              <p className="text-red-400 text-sm mt-1">{errors.location}</p>
            )}
          </div>

          {/* Category and Block - Side by side */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Category */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Category *
              </label>
              <select
                value={formData.category}
                onChange={(e) => handleInputChange('category', e.target.value)}
                className={`w-full px-4 py-2 bg-gray-800 border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                  errors.category ? 'border-red-500' : 'border-gray-600'
                }`}
                disabled={isLoading}
              >
                <option value="">Select Category</option>
                {categories.map(category => (
                  <option key={category.value} value={category.value}>{category.label}</option>
                ))}
              </select>
              {errors.category && (
                <p className="text-red-400 text-sm mt-1">{errors.category}</p>
              )}
            </div>

            {/* Block */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Block *
              </label>
              <select
                value={formData.block}
                onChange={(e) => handleInputChange('block', e.target.value)}
                className={`w-full px-4 py-2 bg-gray-800 border rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                  errors.block ? 'border-red-500' : 'border-gray-600'
                }`}
                disabled={isLoading}
              >
                <option value="">Select Block</option>
                {blocks.map(block => (
                  <option key={block.value} value={block.value}>{block.label}</option>
                ))}
              </select>
              {errors.block && (
                <p className="text-red-400 text-sm mt-1">{errors.block}</p>
              )}
            </div>
          </div>

          {/* Department */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Department
            </label>
            <select
              value={formData.department}
              onChange={(e) => handleInputChange('department', e.target.value)}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabled={isLoading}
            >
              {departments.map(department => (
                <option key={department.value} value={department.value}>{department.label}</option>
              ))}
            </select>
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Description
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => handleInputChange('description', e.target.value)}
              rows={3}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Additional details about this key..."
              disabled={isLoading}
            />
          </div>

          {/* Frequently Used */}
          <div className="flex items-center">
            <input
              type="checkbox"
              id="frequentlyUsed"
              checked={formData.frequentlyUsed}
              onChange={(e) => handleInputChange('frequentlyUsed', e.target.checked)}
              className="w-4 h-4 text-blue-600 bg-gray-800 border-gray-600 rounded focus:ring-blue-500"
              disabled={isLoading}
            />
            <label htmlFor="frequentlyUsed" className="ml-2 text-sm text-gray-300">
              Mark as frequently used
            </label>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  {initialData ? 'Updating...' : 'Creating...'}
                </>
              ) : (
                <>
                  {initialData ? <Save className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
                  {initialData ? 'Update Key' : 'Create Key'}
                </>
              )}
            </button>
          </div>
        </form>
      </motion.div>
    </div>
  );
};

export default KeyForm;
