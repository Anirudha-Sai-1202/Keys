import { motion } from "framer-motion";
import { useAuthStore } from "../../store/authStore";
import { useSidebar } from "../../components/layout/DashboardLayout";
import { useState, useEffect } from "react";
import { 
	Ticket, 
	CheckCircle, 
	Clock, 
	TrendingUp, 
	Activity,
	AlertCircle,
	FileText,
	Calendar
} from "lucide-react";

const OperatorDashboard = () => {
	const { user, fetchDashboardData } = useAuthStore();
	const { sidebarOpen } = useSidebar();
	const [dashboardData, setDashboardData] = useState(null);
	const [loading, setLoading] = useState(true);

	useEffect(() => {
		const loadDashboardData = async () => {
			try {
				const data = await fetchDashboardData();
				setDashboardData(data.data);
			} catch (error) {
				console.error("Failed to load operator dashboard data:", error);
			} finally {
				setLoading(false);
			}
		};

		loadDashboardData();
	}, [fetchDashboardData]);

	const operatorStats = dashboardData?.stats || {
		activeTickets: 0,
		resolvedTickets: 0,
		pendingTasks: 0,
		completedTasks: 0
	};

	const statsCards = [
		{ 
			icon: Ticket, 
			label: "Active Tickets", 
			value: operatorStats.activeTickets, 
			color: "from-orange-500 to-orange-600",
			change: "+3 today"
		},
		{ 
			icon: CheckCircle, 
			label: "Resolved Tickets", 
			value: operatorStats.resolvedTickets, 
			color: "from-green-500 to-green-600",
			change: "+8 this week"
		},
		{ 
			icon: Clock, 
			label: "Pending Tasks", 
			value: operatorStats.pendingTasks, 
			color: "from-blue-500 to-blue-600",
			change: "-2 today"
		},
		{ 
			icon: TrendingUp, 
			label: "Completed Tasks", 
			value: operatorStats.completedTasks, 
			color: "from-purple-500 to-purple-600",
			change: "+15 this week"
		},
	];

	const recentActivity = dashboardData?.recentActivity || [];

	const priorityTasks = [
		{ id: 1, title: "System Maintenance", priority: "High", dueDate: "Today", status: "In Progress" },
		{ id: 2, title: "User Access Review", priority: "Medium", dueDate: "Tomorrow", status: "Pending" },
		{ id: 3, title: "Backup Verification", priority: "High", dueDate: "Today", status: "Pending" },
		{ id: 4, title: "Security Audit", priority: "Low", dueDate: "Next Week", status: "Scheduled" },
	];

	const getPriorityColor = (priority) => {
		switch (priority) {
			case 'High': return 'text-red-400 bg-red-900/20';
			case 'Medium': return 'text-yellow-400 bg-yellow-900/20';
			case 'Low': return 'text-green-400 bg-green-900/20';
			default: return 'text-gray-400 bg-gray-900/20';
		}
	};

	if (loading) {
		return (
			<div className="flex items-center justify-center h-full">
				<div className="animate-spin rounded-full h-32 w-32 border-b-2 border-green-500"></div>
			</div>
		);
	}

	return (
		<div className={`p-6 transition-all duration-300 ${sidebarOpen ? 'ml-0' : 'ml-0'}`}>
			{/* Header */}
			<motion.div
				initial={{ opacity: 0, y: -20 }}
				animate={{ opacity: 1, y: 0 }}
				transition={{ duration: 0.5 }}
				className="mb-8"
			>
				<h1 className="text-3xl font-bold text-white mb-2">
					Operator Dashboard
				</h1>
				<p className="text-gray-300">
					Welcome back, {user?.name}! Here's your operational overview.
				</p>
			</motion.div>

			{/* Stats Cards */}
			<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
				{statsCards.map((stat, index) => (
					<motion.div
						key={stat.label}
						initial={{ opacity: 0, y: 20 }}
						animate={{ opacity: 1, y: 0 }}
						transition={{ duration: 0.5, delay: index * 0.1 }}
						className="bg-gray-800 bg-opacity-50 backdrop-filter backdrop-blur-xl rounded-xl p-6 border border-gray-700"
					>
						<div className="flex items-center justify-between">
							<div>
								<p className="text-gray-400 text-sm font-medium">{stat.label}</p>
								<p className="text-2xl font-bold text-white mt-1">{stat.value}</p>
								<p className="text-green-400 text-sm mt-1">{stat.change}</p>
							</div>
							<div className={`p-3 rounded-lg bg-gradient-to-r ${stat.color}`}>
								<stat.icon className="h-6 w-6 text-white" />
							</div>
						</div>
					</motion.div>
				))}
			</div>

			{/* Content Grid */}
			<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
				{/* Priority Tasks */}
				<motion.div
					initial={{ opacity: 0, x: -20 }}
					animate={{ opacity: 1, x: 0 }}
					transition={{ duration: 0.5, delay: 0.4 }}
					className="bg-gray-800 bg-opacity-50 backdrop-filter backdrop-blur-xl rounded-xl p-6 border border-gray-700"
				>
					<h3 className="text-xl font-semibold text-white mb-4 flex items-center">
						<AlertCircle className="h-5 w-5 mr-2" />
						Priority Tasks
					</h3>
					<div className="space-y-3">
                        {priorityTasks.map((task) => (
							<div key={task.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
								<div className="flex-1">
									<p className="text-white font-medium">{task.title}</p>
									<div className="flex items-center mt-1 space-x-2">
										<span className={`px-2 py-1 rounded-full text-xs font-medium ${getPriorityColor(task.priority)}`}>
											{task.priority}
										</span>
										<span className="text-gray-400 text-xs flex items-center">
											<Calendar className="h-3 w-3 mr-1" />
											{task.dueDate}
										</span>
									</div>
								</div>
								<div className="text-right">
									<span className="text-gray-300 text-sm">{task.status}</span>
								</div>
							</div>
						))}
					</div>
				</motion.div>

				{/* Recent Activity */}
				<motion.div
					initial={{ opacity: 0, x: 20 }}
					animate={{ opacity: 1, x: 0 }}
					transition={{ duration: 0.5, delay: 0.5 }}
					className="bg-gray-800 bg-opacity-50 backdrop-filter backdrop-blur-xl rounded-xl p-6 border border-gray-700"
				>
					<h3 className="text-xl font-semibold text-white mb-4 flex items-center">
						<Activity className="h-5 w-5 mr-2" />
						Recent Activity
					</h3>
					<div className="space-y-3">
                        {recentActivity.length > 0 ? recentActivity.map((activity) => (
							<div key={activity.id} className="flex items-start space-x-3 py-2">
								<div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
								<div className="flex-1">
									<p className="text-white text-sm">{activity.action}</p>
									<p className="text-gray-400 text-xs">
										{new Date(activity.timestamp).toLocaleString()}
									</p>
								</div>
							</div>
						)) : (
							<div className="text-center py-8">
								<Activity className="h-12 w-12 text-gray-600 mx-auto mb-3" />
								<p className="text-gray-400">No recent activity</p>
							</div>
						)}
					</div>
				</motion.div>
			</div>

			{/* Quick Actions */}
			<motion.div
				initial={{ opacity: 0, y: 20 }}
				animate={{ opacity: 1, y: 0 }}
				transition={{ duration: 0.5, delay: 0.6 }}
				className="mt-8 bg-gray-800 bg-opacity-50 backdrop-filter backdrop-blur-xl rounded-xl p-6 border border-gray-700"
			>
				<h3 className="text-xl font-semibold text-white mb-4 flex items-center">
					<FileText className="h-5 w-5 mr-2" />
					Quick Actions
				</h3>
				<div className="grid grid-cols-1 md:grid-cols-4 gap-4">
					<button className="flex items-center justify-center p-4 bg-orange-600 hover:bg-orange-700 rounded-lg transition-colors">
						<Ticket className="h-5 w-5 mr-2" />
						<span className="text-white font-medium">New Ticket</span>
					</button>
					<button className="flex items-center justify-center p-4 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
						<Clock className="h-5 w-5 mr-2" />
						<span className="text-white font-medium">View Tasks</span>
					</button>
					<button className="flex items-center justify-center p-4 bg-green-600 hover:bg-green-700 rounded-lg transition-colors">
						<CheckCircle className="h-5 w-5 mr-2" />
						<span className="text-white font-medium">Mark Complete</span>
					</button>
					<button className="flex items-center justify-center p-4 bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors">
						<FileText className="h-5 w-5 mr-2" />
						<span className="text-white font-medium">Generate Report</span>
					</button>
				</div>
			</motion.div>
		</div>
	);
};

export default OperatorDashboard;
