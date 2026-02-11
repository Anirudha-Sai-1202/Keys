import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { 
  Clock, 
  User, 
  Key, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw,
  Filter
} from "lucide-react";
import axios from "axios";

const AuditLogViewer = ({ keyId = null, userId = null, showCollectiveOnly = false }) => {
  const [auditLogs, setAuditLogs] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filters, setFilters] = useState({
    action: '',
    dateFrom: '',
    dateTo: '',
    limit: 50
  });

  const fetchAuditLogs = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    
    try {
      let url = '/api/audit';
      
      if (showCollectiveOnly) {
        url = '/api/audit/collective-returns';
      } else if (keyId) {
        url = `/api/audit/key/${keyId}`;
      } else if (userId) {
        url = `/api/audit/user/${userId}`;
      }

      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });

      const response = await axios.get(`${url}?${params.toString()}`, {
        withCredentials: true
      });

      setAuditLogs(response.data.data.logs || []);
    } catch (err) {
      console.error('Error fetching audit logs:', err);
      setError('Failed to fetch audit logs');
    } finally {
      setIsLoading(false);
    }
  }, [keyId, userId, showCollectiveOnly, filters]);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs]);

  const getActionIcon = (action) => {
    switch (action) {
      case 'key_taken':
        return <Key className="w-4 h-4 text-blue-400" />;
      case 'key_returned':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'key_collective_return':
        return <AlertTriangle className="w-4 h-4 text-orange-400" />;
      case 'qr_scan_request':
      case 'qr_scan_return':
        return <RefreshCw className="w-4 h-4 text-purple-400" />;
      case 'manual_collection':
        return <User className="w-4 h-4 text-yellow-400" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getActionLabel = (action) => {
    switch (action) {
      case 'key_taken':
        return 'Key Taken';
      case 'key_returned':
        return 'Key Returned';
      case 'key_collective_return':
        return 'Collective Return';
      case 'qr_scan_request':
        return 'QR Scan Request';
      case 'qr_scan_return':
        return 'QR Scan Return';
      case 'manual_collection':
        return 'Manual Collection';
      default:
        return action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  const getTimeAgo = (dateString) => {
    const now = new Date();
    const date = new Date(dateString);
    const diffInMinutes = Math.floor((now - date) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours}h ago`;
    
    const diffInDays = Math.floor(diffInHours / 24);
    return `${diffInDays}d ago`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-8">
        <RefreshCw className="w-6 h-6 text-blue-400 animate-spin mr-2" />
        <span className="text-gray-300">Loading audit logs...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 text-center">
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <p className="text-red-400 text-lg">{error}</p>
        <button
          onClick={fetchAuditLogs}
          className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-gray-800 rounded-xl p-4 border border-gray-700">
        <div className="flex items-center space-x-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">Filters</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Action</label>
            <select
              value={filters.action}
              onChange={(e) => setFilters(prev => ({ ...prev, action: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
            >
              <option value="">All Actions</option>
              <option value="key_taken">Key Taken</option>
              <option value="key_returned">Key Returned</option>
              <option value="key_collective_return">Collective Return</option>
              <option value="qr_scan_request">QR Scan Request</option>
              <option value="qr_scan_return">QR Scan Return</option>
              <option value="manual_collection">Manual Collection</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">From Date</label>
            <input
              type="date"
              value={filters.dateFrom}
              onChange={(e) => setFilters(prev => ({ ...prev, dateFrom: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">To Date</label>
            <input
              type="date"
              value={filters.dateTo}
              onChange={(e) => setFilters(prev => ({ ...prev, dateTo: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Limit</label>
            <select
              value={filters.limit}
              onChange={(e) => setFilters(prev => ({ ...prev, limit: parseInt(e.target.value) }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
            >
              <option value={25}>25 entries</option>
              <option value={50}>50 entries</option>
              <option value={100}>100 entries</option>
              <option value={200}>200 entries</option>
            </select>
          </div>
        </div>
      </div>

      {/* Audit Logs */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="p-6 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-white">
              {showCollectiveOnly ? 'Collective Return Logs' : 'Audit Trail'}
            </h2>
            <button
              onClick={fetchAuditLogs}
              className="flex items-center space-x-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors text-sm"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Refresh</span>
            </button>
          </div>
          <p className="text-gray-400 mt-1">{auditLogs.length} entries found</p>
        </div>

        {auditLogs.length === 0 ? (
          <div className="p-8 text-center">
            <Clock className="w-12 h-12 text-gray-500 mx-auto mb-4" />
            <p className="text-gray-400 text-lg">No audit logs found</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-700">
            {auditLogs.map((log, index) => (
              <motion.div
                key={log._id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="p-6 hover:bg-gray-750 transition-colors"
              >
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0 mt-1">
                    {getActionIcon(log.action)}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="text-white font-medium">
                          {getActionLabel(log.action)}
                        </span>
                        {log.metadata?.isCollectiveReturn && (
                          <span className="px-2 py-1 bg-orange-600 text-white text-xs rounded-full">
                            Collective
                          </span>
                        )}
                      </div>
                      <span className="text-gray-400 text-sm">{getTimeAgo(log.createdAt)}</span>
                    </div>
                    
                    <div className="mt-2 space-y-1">
                      <p className="text-gray-300">
                        <span className="font-medium">Key:</span> {log.keyDetails.keyNumber} - {log.keyDetails.keyName}
                      </p>
                      <p className="text-gray-300">
                        <span className="font-medium">Location:</span> {log.keyDetails.location}
                      </p>
                      <p className="text-gray-300">
                        <span className="font-medium">Performed by:</span> {log.performedBy.name} ({log.performedBy.role})
                      </p>
                      
                      {log.originalUser && (
                        <p className="text-gray-300">
                          <span className="font-medium">Original user:</span> {log.originalUser.name}
                        </p>
                      )}
                      
                      {log.metadata?.reason && (
                        <p className="text-gray-300">
                          <span className="font-medium">Reason:</span> {log.metadata.reason}
                        </p>
                      )}
                    </div>
                    
                    <p className="text-gray-500 text-sm mt-2">{formatDate(log.createdAt)}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AuditLogViewer;
