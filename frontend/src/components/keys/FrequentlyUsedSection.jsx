import KeyCard from "./KeyCard";
import { TrendingUp } from "lucide-react";

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

const FrequentlyUsedSection = ({
	keys,
	availabilityFilter,
	onRequestKey,
	usageCounts = {},
}) => {
	const filtered = applyAvailabilityFilter(keys, availabilityFilter).slice(0, 5); // ✅ limit to 5

	return (
		<div className="mb-8">
			<h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
				<TrendingUp className="w-5 h-5" />
				Frequently Used Keys
			</h3>
			
			{filtered.length === 0 ? (
				<div className="text-center py-8 bg-white/5 rounded-xl border border-white/10">
					<TrendingUp className="w-12 h-12 text-gray-400 mx-auto mb-3" />
					<p className="text-gray-400 text-lg">No frequently used keys yet</p>
					<p className="text-gray-500 text-sm mt-1">
						Keys you use most often will appear here
					</p>
				</div>
			) : (
				<div className="flex gap-4 overflow-x-auto pb-4 scrollbar-hide">
					{filtered.map((key) => (
						<div key={key.id} className="flex-shrink-0 w-80">
							<KeyCard
								keyData={key}
								variant="default"
								onRequestKey={onRequestKey}
								usageCount={usageCounts[key.id]}
							/>
						</div>
					))}
				</div>
			)}
		</div>
	);
};

export default FrequentlyUsedSection;
