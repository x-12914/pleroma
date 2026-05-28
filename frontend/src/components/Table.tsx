import type { ReactNode } from 'react';

interface TableColumn {
  key: string;
  label: string;
  width?: string;
  render?: (value: any, row: any) => ReactNode;
  className?: string;
}

interface TableProps {
  columns: TableColumn[];
  data: any[];
  loading?: boolean;
  empty?: string;
}

export default function Table({ columns, data, loading = false, empty = 'No data available' }: TableProps) {
  if (loading) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 bg-dark-800 rounded animate-pulse" />
        ))}
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="text-center py-8 text-gray-400">
        {empty}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-dark-700 text-left text-sm font-semibold text-gray-400">
            {columns.map((col) => (
              <th key={col.key} className={`px-4 py-3 ${col.width || ''} ${col.className || ''}`}>
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, idx) => (
            <tr
              key={idx}
              className="border-b border-dark-700/50 hover:bg-dark-800/50 transition-colors duration-200 text-sm"
            >
              {columns.map((col) => (
                <td key={`${idx}-${col.key}`} className={`px-4 py-3 text-gray-300 ${col.width || ''} ${col.className || ''}`}>
                  {col.render ? col.render(row[col.key], row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
