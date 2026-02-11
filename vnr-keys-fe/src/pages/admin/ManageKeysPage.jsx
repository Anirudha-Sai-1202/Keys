import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Key, 
  Plus, 
  Search, 
  Edit, 
  Trash2, 
  MoreVertical,
  CheckCircle,
  XCircle,
  Star,
  MapPin,
  Building
} from 'lucide-react';
import { useKeyStore } from '../../store/keyStore';
import KeyForm from '../../components/admin/KeyForm';

const ManageKeysPage = () => {
  const {
    keys,
    isLoading,
    fetchKeys,
    createKey,
    updateKey,
    deleteKey
  } = useKeyStore();

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [showKeyForm, setShowKeyForm] = useState(false);
  const [editingKey, setEditingKey] = useState(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [keyToDelete, setKeyToDelete] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    fetchKeys();
  }, [fetchKeys]);

  // Filter keys based on search and filters
  const filteredKeys = keys.filter(key => {
    const matchesSearch = 
      key.keyNumber.toLowerCase().includes(searchQuery.toLowerCase()) ||
      key.keyName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      key.location.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesStatus = statusFilter === 'all' || key.status === statusFilter;
    
    const matchesCategory = categoryFilter === 'all' || key.category === categoryFilter;

    return matchesSearch && matchesStatus && matchesCategory;
  });

  // Get unique categories for filter
  const categories = [...new Set(keys.map(key => key.category).filter(Boolean))];

  const handleCreateKey = async (keyData) => {
    try {
      setIsSubmitting(true);
      await createKey(keyData);
      setShowKeyForm(false);
    } catch (error) {
      console.error('Error creating key:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUpdateKey = async (keyData) => {
    try {
      setIsSubmitting(true);
      await updateKey(editingKey.id, keyData);
      setShowKeyForm(false);
      setEditingKey(null);
    } catch (error) {
      console.error('Error updating key:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteKey = async () => {
    if (!keyToDelete) return;

    try {
      setIsSubmitting(true);
      await deleteKey(keyToDelete.id);
      setShowDeleteModal(false);
      setKeyToDelete(null);
    } catch (error) {
      console.error('Error deleting key:', error);
    } finally {
      setIsSubmitting(false);
    }
  };

  const openEditModal = (key) => {
    setEditingKey(key);
    setShowKeyForm(true);
  };

  const openDeleteModal = (key) => {
    setKeyToDelete(key);
    setShowDeleteModal(true);
  };

  const closeModals = () => {
    setShowKeyForm(false);
    setEditingKey(null);
    setShowDeleteModal(false);
    setKeyToDelete(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-3">
            <Key className="w-8 h-8 text-blue-400" />
            Manage Keys
          </h1>
          <p className="text-gray-400">
            Add, edit, and manage all keys in the system
          </p>
        </motion.div>

        {/* Controls */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-gray-800 rounded-xl p-6 mb-6 border border-gray-700"
        >
          <div className="flex flex-col lg:flex-row gap-4 items-start lg:items-center justify-between">
            {/* Search and Filters */}
            <div className="flex flex-col sm:flex-row gap-4 flex-1">
              {/* Search */}
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                <input
                  type="text"
                  placeholder="Search keys..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              {/* Status Filter */}
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Status</option>
                <option value="available">Available</option>
                <option value="unavailable">Unavailable</option>
              </select>

              {/* Category Filter */}
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Categories</option>
                {categories.map(category => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
            </div>

            {/* Add Key Button */}
            <button
              onClick={() => setShowKeyForm(true)}
              className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-colors flex items-center gap-2"
            >
              <Plus className="w-5 h-5" />
              Add New Key
            </button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-gray-700">
            <div className="text-center">
              <div className="text-2xl font-bold text-white">{keys.length}</div>
              <div className="text-sm text-gray-400">Total Keys</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-400">
                {keys.filter(k => k.status === 'available').length}
              </div>
              <div className="text-sm text-gray-400">Available</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-400">
                {keys.filter(k => k.status === 'unavailable').length}
              </div>
              <div className="text-sm text-gray-400">Unavailable</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-400">
                {keys.filter(k => k.frequentlyUsed).length}
              </div>
              <div className="text-sm text-gray-400">Frequently Used</div>
            </div>
          </div>
        </motion.div>

        {/* Keys Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden"
        >
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
            </div>
          ) : filteredKeys.length === 0 ? (
            <div className="text-center py-12">
              <Key className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-400 text-lg">No keys found</p>
              <p className="text-gray-500 text-sm mt-1">
                {searchQuery || statusFilter !== 'all' || categoryFilter !== 'all'
                  ? 'Try adjusting your search or filters'
                  : 'Add your first key to get started'
                }
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-700">
                  <tr>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-300">Key Info</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-300">Location</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-300">Status</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-300">Category</th>
                    <th className="px-6 py-4 text-left text-sm font-medium text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredKeys.map((key) => (
                    <KeyTableRow
                      key={key.id}
                      keyData={key}
                      onEdit={openEditModal}
                      onDelete={openDeleteModal}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </motion.div>
      </div>

      {/* Key Form Modal */}
      <KeyForm
        isOpen={showKeyForm}
        onClose={closeModals}
        onSubmit={editingKey ? handleUpdateKey : handleCreateKey}
        initialData={editingKey}
        isLoading={isSubmitting}
        title={editingKey ? "Edit Key" : "Add New Key"}
      />

      {/* Delete Confirmation Modal */}
      {showDeleteModal && keyToDelete && (
        <DeleteConfirmationModal
          isOpen={showDeleteModal}
          onClose={closeModals}
          onConfirm={handleDeleteKey}
          keyData={keyToDelete}
          isLoading={isSubmitting}
        />
      )}
    </div>
  );
};

// Key Table Row Component
const KeyTableRow = ({ keyData, onEdit, onDelete }) => {
  const [showActions, setShowActions] = useState(false);

  return (
    <tr className="hover:bg-gray-700/50 transition-colors">
      <td className="px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex-shrink-0">
            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center">
              <Key className="w-5 h-5 text-white" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium text-white">{keyData.keyNumber}</span>
              {keyData.frequentlyUsed && (
                <Star className="w-4 h-4 text-yellow-400 fill-current" />
              )}
            </div>
            <div className="text-sm text-gray-400">{keyData.keyName}</div>
          </div>
        </div>
      </td>
      <td className="px-6 py-4">
        <div className="flex items-center gap-2 text-gray-300">
          <MapPin className="w-4 h-4 text-gray-400" />
          <span>{keyData.location}</span>
        </div>
        {keyData.block && (
          <div className="flex items-center gap-2 text-sm text-gray-400 mt-1">
            <Building className="w-3 h-3" />
            <span>{keyData.block}</span>
          </div>
        )}
      </td>
      <td className="px-6 py-4">
        <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${
          keyData.status === 'available'
            ? 'bg-green-900/50 text-green-400 border border-green-700'
            : 'bg-red-900/50 text-red-400 border border-red-700'
        }`}>
          {keyData.status === 'available' ? (
            <CheckCircle className="w-3 h-3" />
          ) : (
            <XCircle className="w-3 h-3" />
          )}
          {keyData.status === 'available' ? 'Available' : 'Unavailable'}
        </span>
      </td>
      <td className="px-6 py-4">
        <span className="text-gray-300">{keyData.category || 'N/A'}</span>
      </td>
      <td className="px-6 py-4">
        <div className="relative">
          <button
            onClick={() => setShowActions(!showActions)}
            className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-600 transition-colors"
          >
            <MoreVertical className="w-4 h-4" />
          </button>
          
          {showActions && (
            <div className="absolute right-0 top-full mt-1 bg-gray-700 rounded-lg shadow-lg border border-gray-600 z-10 min-w-[120px]">
              <button
                onClick={() => {
                  onEdit(keyData);
                  setShowActions(false);
                }}
                className="w-full px-4 py-2 text-left text-gray-300 hover:text-white hover:bg-gray-600 flex items-center gap-2 transition-colors"
              >
                <Edit className="w-4 h-4" />
                Edit
              </button>
              <button
                onClick={() => {
                  onDelete(keyData);
                  setShowActions(false);
                }}
                className="w-full px-4 py-2 text-left text-red-400 hover:text-red-300 hover:bg-gray-600 flex items-center gap-2 transition-colors"
              >
                <Trash2 className="w-4 h-4" />
                Delete
              </button>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
};

// Delete Confirmation Modal Component
const DeleteConfirmationModal = ({ isOpen, onClose, onConfirm, keyData, isLoading }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className="bg-gray-900 rounded-xl p-6 max-w-md w-full border border-gray-700"
      >
        <div className="text-center">
          <div className="w-12 h-12 bg-red-600/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <Trash2 className="w-6 h-6 text-red-400" />
          </div>
          
          <h3 className="text-xl font-bold text-white mb-2">Delete Key</h3>
          <p className="text-gray-400 mb-6">
            Are you sure you want to delete key <strong>{keyData.keyNumber}</strong>? 
            This action cannot be undone.
          </p>

          <div className="flex gap-3">
            <button
              onClick={onClose}
              className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              onClick={onConfirm}
              className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Deleting...
                </>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  Delete
                </>
              )}
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default ManageKeysPage;
