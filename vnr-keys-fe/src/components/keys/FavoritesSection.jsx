import KeyCard from "./KeyCard";
import { Star } from "lucide-react";

const applyAvailabilityFilter = (keys, filter) => {
	switch (filter) {
		case "available":
			return keys.filter((k) => k.status === "available");
		case "unavailable":
			return keys.filter((k) => k.status !== "available");
		case "favorites":
			return keys.filter((k) => k.frequentlyUsed);
		default:
			return keys;
	}
};

const FavoritesSection = ({
	keys,
	availabilityFilter,
	onRequestKey,
	onToggleFrequent,
}) => {
	const favoriteKeys = keys.filter((k) => k.frequentlyUsed);
	const filtered = applyAvailabilityFilter(favoriteKeys, availabilityFilter);

	return (
		<div className="mb-8">
			<h3 className="text-lg font-semibold text-white mb-4">Favorites</h3>
			
			{filtered.length === 0 ? (
				<div className="text-center py-8 bg-white/5 rounded-xl border border-white/10">
					<Star className="w-12 h-12 text-gray-400 mx-auto mb-3" />
					<p className="text-gray-400 text-lg">No favorites added yet</p>
					<p className="text-gray-500 text-sm mt-1">
						Tap the star icon on any key to add it to favorites
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
								onToggleFrequent={onToggleFrequent}
							/>
						</div>
					))}
				</div>
			)}
		</div>
	);
};

export default FavoritesSection;



