import { useMemo } from "react";
import KeyCard from "./KeyCard";
import { ChevronRight, ChevronDown } from "lucide-react";
import { getBlockInfo } from "../../utils/keyFormatters";

// Lightweight accordion implemented inline to avoid dependency wiring
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

const matchesSearch = (key, query) => {
	if (!query.trim()) return true;
	const term = query.toLowerCase();
	return (
		key.keyName.toLowerCase().includes(term) ||
		String(key.keyNumber).toLowerCase().includes(term) ||
		(key.location || "").toLowerCase().includes(term) ||
		(key.block || "").toLowerCase().includes(term) ||
		(key.description || "").toLowerCase().includes(term)
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

const groupByBlock = (keys) => {
	console.log('Grouping keys by block:', keys);
	const grouped = {};
	for (const key of keys) {
		const block = key.block || "Other";
		if (!grouped[block]) grouped[block] = [];
		grouped[block].push(key);
	}
	console.log('Grouped result:', grouped);
	return grouped;
};

const blockOrder = ["A", "B", "C", "D", "E", "PG"]; // Define the order we want blocks to appear in

const BlockAccordion = ({
	keys = [],
	searchQuery,
	availabilityFilter,
	onRequestKey,
	openState,
	setOpenState,
}) => {
	const grouped = useMemo(() => groupByBlock(keys), [keys]);

	return (
		<div className="space-y-3">
			{blockOrder
				.filter(block => grouped[block])
				.map((block) => {
					const list = grouped[block] || [];
					const filteredBySearch = list.filter((k) => matchesSearch(k, searchQuery));
					const finalList = applyAvailabilityFilter(filteredBySearch, availabilityFilter);

					// Auto-open if search matches exist
					const isOpen = openState[block] || (searchQuery.trim() && finalList.length > 0);
					const toggle = () => setOpenState((prev) => ({ ...prev, [block]: !isOpen }));

					// Hide empty blocks when a search is active
					if (searchQuery.trim() && finalList.length === 0) return null;



					const { name, description } = getBlockInfo(block);
					const title = `${name} - ${description}`;

					return (
						<AccordionItem
							key={block}
							title={title}
							isOpen={isOpen}
							onToggle={toggle}
							count={finalList.length}
						>
							{finalList.length === 0 ? (
								<div className="text-center py-4">
									<p className="text-gray-400">No keys found</p>
								</div>
							) : (
								<div className="grid gap-3">
									{finalList.map((key) => (
										<KeyCard
											key={key.id}
											keyData={key}
											onRequestKey={() => onRequestKey(key)}
										/>
									))}
								</div>
							)}
						</AccordionItem>
					);
				})}
		</div>
	);
};

export default BlockAccordion;
