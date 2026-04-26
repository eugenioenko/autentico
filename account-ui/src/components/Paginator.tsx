import React from 'react';
import { IconChevronLeft, IconChevronRight } from '@tabler/icons-react';

interface PaginatorProps {
  offset: number;
  limit: number;
  total: number;
  onPageChange: (newOffset: number) => void;
}

const Paginator: React.FC<PaginatorProps> = ({ offset, limit, total, onPageChange }) => {
  if (total <= limit) return null;

  const page = Math.floor(offset / limit) + 1;
  const totalPages = Math.ceil(total / limit);
  const hasPrev = offset > 0;
  const hasNext = offset + limit < total;

  return (
    <div className="flex items-center justify-between pt-3">
      <p className="text-xs text-theme-muted">
        {offset + 1}–{Math.min(offset + limit, total)} of {total}
      </p>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onPageChange(offset - limit)}
          disabled={!hasPrev}
          className="p-1.5 rounded-brand text-theme-muted hover:text-theme-fg hover:bg-theme-fg/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <IconChevronLeft size={16} />
        </button>
        <span className="text-xs text-theme-muted px-2">
          {page} / {totalPages}
        </span>
        <button
          onClick={() => onPageChange(offset + limit)}
          disabled={!hasNext}
          className="p-1.5 rounded-brand text-theme-muted hover:text-theme-fg hover:bg-theme-fg/5 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          <IconChevronRight size={16} />
        </button>
      </div>
    </div>
  );
};

export default Paginator;
