import { useMemo } from "react";
import DepartmentCard from "./DepartmentCard";

const DEPARTMENTS = [
	{ value: "Accounts", label: "Accounts" },
	{ value: "Admission", label: "Admission" },
	{ value: "Automobile", label: "Automobile" },
	{ value: "CAMS", label: "CAMS" },
	{ value: "Chemistry", label: "Chemistry" },
	{ value: "Civil", label: "Civil" },
	{ value: "CSE", label: "CSE" },
	{ value: "CSE-AIML&IOT", label: "CSE-AIML&IOT" },
	{ value: "CSE-(CyS,DS)_and_AI&DS", label: "CSE-(CyS,DS)_and_AI&DS" },
	{ value: "Director", label: "Director" },
	{ value: "EEE", label: "EEE" },
	{ value: "ECE", label: "ECE" },
	{ value: "EIE", label: "EIE" },
	{ value: "English", label: "English" },
	{ value: "GRO", label: "GRO" },
	{ value: "HR", label: "HR" },
	{ value: "Humanity and sciences(H&S)", label: "Humanity and sciences(H&S)" },
	{ value: "IQAC", label: "IQAC" },
	{ value: "IT", label: "IT" },
	{ value: "MECH", label: "MECH" },
	{ value: "Other", label: "Other" },
	{ value: "PAAC", label: "PAAC" },
	{ value: "Placement", label: "Placement" },
	{ value: "Principal", label: "Principal" },
	{ value: "Purchase", label: "Purchase" },
	{ value: "RCC", label: "RCC" },
	{ value: "SSC", label: "SSC" },
	{ value: "VJ_Hub", label: "VJ_Hub" }
];

const DepartmentsSection = ({ keys, onDepartmentClick, selectedDepartment }) => {
	const counts = useMemo(() => {
		const map = {};
		for (const dept of DEPARTMENTS) map[dept.value] = 0;
		for (const key of keys) {
			const dept = key.department;
			if (dept && Object.prototype.hasOwnProperty.call(map, dept)) map[dept] += 1;
		}
		return map;
	}, [keys]);

	const sortedDepartments = useMemo(() => {
		return [...DEPARTMENTS].sort((a, b) => {
			const countA = counts[a.value] || 0;
			const countB = counts[b.value] || 0;
			return countB - countA; // Descending order
		});
	}, [counts]);

	return (
		<div className="mb-8">
			<h3 className="text-lg font-semibold text-white mb-4">Departments</h3>
			<div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
				{sortedDepartments.map(({ value, label }) => (
					<DepartmentCard
						key={value}
						department={label}
						keyCount={counts[value] || 0}
						onClick={() => onDepartmentClick(value)}
						isSelected={selectedDepartment === value}
					/>
				))}
			</div>
		</div>
	);
};

export default DepartmentsSection;
