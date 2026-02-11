import { useMemo } from "react";
import DepartmentCard from "./DepartmentCard";

const groupByBlock = (keys) => {
	const grouped = {};
	for (const key of keys) {
		const block = key.block || "Unknown";
		if (!grouped[block]) grouped[block] = [];
		grouped[block].push(key);
	}
	return grouped;
};

const BlocksSection = ({ keys, onBlockClick, selectedBlock }) => {
	const grouped = useMemo(() => groupByBlock(keys), [keys]);

	// Order blocks A,B,C,D,E,PG then others
	const preferredOrder = ["A", "B", "C", "D", "E", "PG"];
	const sortedBlocks = Object.entries(grouped)
		.sort(([, a], [, b]) => b.length - a.length)
		.sort(([a], [b]) => {
			const ia = preferredOrder.indexOf(a);
			const ib = preferredOrder.indexOf(b);
			if (ia === -1 && ib === -1) return 0;
			if (ia === -1) return 1;
			if (ib === -1) return -1;
			return ia - ib;
		})
		.map(([block, blockKeys]) => ({
			block,
			keyCount: blockKeys.length
		}));

	return (
		<div className="mb-8">
			<h3 className="text-lg font-semibold text-white mb-4">Blocks</h3>
			{sortedBlocks.length === 0 ? (
				<div className="text-center py-8 bg-white/5 rounded-xl border border-white/10">
					<p className="text-gray-400 text-lg">No blocks found</p>
				</div>
			) : (
				<div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
					{sortedBlocks.map(({ block, keyCount }) => (
						<DepartmentCard
							key={block}
							department={block}
							keyCount={keyCount}
							onClick={() => onBlockClick(block)}
							isSelected={selectedBlock === block}
						/>
					))}
				</div>
			)}
		</div>
	);
};

export default BlocksSection; 