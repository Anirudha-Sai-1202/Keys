import { getBlockInfo } from '../../utils/keyFormatters';

const BlockCard = ({ block, keyCount, onClick, isSelected = false }) => {
	const { name, description } = getBlockInfo(block);

	return (
		<button
			onClick={onClick}
			className={`w-full p-4 rounded-xl transition-all duration-200 text-left ${
				isSelected
					? "bg-green-500/20 border-green-500"
					: "bg-white/5 hover:bg-white/10 border-white/20"
			} border`}
		>
			<div className="flex items-start justify-between">
				<div>
					<h4 className="text-white font-medium mb-1">{name}</h4>
					<p className="text-sm text-gray-400 line-clamp-2">{description}</p>
				</div>
				<span className="ml-2 px-2 py-1 bg-white/10 rounded text-xs text-white">
					{keyCount}
				</span>
			</div>
		</button>
	);
};

export default BlockCard;
