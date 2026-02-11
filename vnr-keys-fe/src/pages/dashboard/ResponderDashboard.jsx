import { useSidebar } from "../../components/layout/DashboardLayout";
// Icons reserved for future UI

const ResponderDashboard = () => {
    const { sidebarOpen } = useSidebar();

    // Derive stats when rendering specific sections

    // Stats cards will be rendered in a future iteration

    // const recentIncidents = dashboardData?.recentIncidents || [];

    return (
        <div className={`p-6 transition-all duration-300 ${sidebarOpen ? 'ml-0' : 'ml-0'}`}>
            {/* Placeholder content to avoid unused variables; implement UI later */}
            <h1 className="text-2xl text-white">Responder Dashboard</h1>
        </div>
    );
};

export default ResponderDashboard;
