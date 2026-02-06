import { useMemo } from "react";
import KeyCard from "./KeyCard";
import { ChevronRight, ChevronDown } from "lucide-react";

// Lightweight accordion (shadcn-like) implemented inline to avoid dependency wiring
const AccordionItem = ({ title, isOpen, onToggle, children, count }) => {
	return (
		<div className="border border-white/20 rounded-lg overflow-hidden bg-white/5">
			<button
				onClick={onToggle}
				className="w-full flex items-center justify-between px-4 py-3 text-left text-white hover:bg-white/10"
			>
				<div className="flex items-center gap-2">
					{isOpen ? (
						<ChevronDown className="w-4 h-4" />
					) : (
						<ChevronRight className="w-4 h-4" />
					)}
					<span className="font-medium">{title}</span>
				</div>
				{typeof count === "number" && (
					<span className="text-xs text-gray-300">{count}</span>
				)}
			</button>
			{isOpen && <div className="p-3 space-y-3">{children}</div>}
		</div>
	);
};

const applyAvailabilityFilter = (keys, filter) => {
	switch (filter) {
		case "available":
			return keys.filter((k) => k.status === "available");
		case "unavailable":
			return keys.filter((k) => k.status !== "available");
		default:
			return keys;
	}
};

const groupByDepartment = (keys) => {
	const grouped = {};
	for (const key of keys) {
		const dept = key.department || "OTHER";
		if (!grouped[dept]) grouped[dept] = [];
		grouped[dept].push(key);
	}
	return grouped;
};

const DepartmentAccordion = ({
	keys,
	availabilityFilter,
	onRequestKey,
	openState,
	setOpenState,
}) => {
	const grouped = useMemo(() => groupByDepartment(keys), [keys]);

	// Standard department order matching backend schema
	const departmentOrder = [
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
		"VJ_Hub",
		// Add any remaining departments found in data
		...Object.keys(grouped).filter(
			(d) => ![
				"Accounts", "Admission", "Automobile", "CAMS", "Chemistry", "Civil", 
				"CSE", "CSE-AIML&IOT", "CSE-(CyS,DS)_and_AI&DS", "Director", "EEE", 
				"ECE", "EIE", "English", "GRO", "HR", "Humanity and sciences(H&S)", 
				"IQAC", "IT", "MECH", "Other", "PAAC", "Placement", "Principal", 
				"Purchase", "RCC", "SSC", "VJ_Hub"
			].includes(d)
		),
	];

	return (
		<div className="space-y-3">
			{departmentOrder
				.filter((dept, idx, arr) => arr.indexOf(dept) === idx)
				.map((dept) => {
					const list = grouped[dept] || [];
					const finalList = applyAvailabilityFilter(list, availabilityFilter);

					// Auto-open if department has keys
					const isOpen = openState[dept] || finalList.length > 0;
					const toggle = () => setOpenState((prev) => ({ ...prev, [dept]: !isOpen }));

					return (
						<AccordionItem
							key={dept}
							title={`${dept} Department`}
							isOpen={isOpen}
							onToggle={toggle}
							count={finalList.length}
						>
							{finalList.length === 0 ? (
								<div className="text-sm text-gray-400 px-1 py-2">No keys</div>
							) : (
								finalList.map((key) => (
									<KeyCard
										key={key.id}
										keyData={key}
										variant="default"
										onRequestKey={onRequestKey}
									/>
								))
							)}
						</AccordionItem>
					);
				})}
		</div>
	);
};

export default DepartmentAccordion;



