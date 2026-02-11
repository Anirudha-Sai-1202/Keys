import { useState } from "react";
import FrequentlyUsedSection from "./FrequentlyUsedSection";
import DepartmentAccordion from "./DepartmentAccordion";

const AllKeysSection = ({
	keys,
	frequentlyUsedKeys = [],
	usageCounts = {},
	availabilityFilter,
	onRequestKey,
}) => {
	const [openState, setOpenState] = useState({});
	return (
		<div>
			{/* Frequently Used Keys */}
			<FrequentlyUsedSection
				keys={frequentlyUsedKeys}
				availabilityFilter={availabilityFilter}
				onRequestKey={onRequestKey}
				usageCounts={usageCounts}
			/>

			{/* All Keys by Department */}
			<div className="mt-2">
				<h3 className="text-lg font-semibold text-white mb-4">All Keys (By Department)</h3>
				<DepartmentAccordion
					keys={keys}
					availabilityFilter={availabilityFilter}
					onRequestKey={onRequestKey}
					openState={openState}
					setOpenState={setOpenState}
				/>
			</div>
		</div>
	);
};

export default AllKeysSection;


