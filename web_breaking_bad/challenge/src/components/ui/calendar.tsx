import * as React from 'react';
import { ChevronLeftIcon, ChevronRightIcon } from '@radix-ui/react-icons';
import CalendarBase, { CalendarProps as ReactCalendarProps } from 'react-calendar';
import 'react-calendar/dist/Calendar.css'; // Import default styles
import { cn } from '@/lib/utils';

// Extend CalendarProps to add custom navigation labels and custom tile rendering
interface CustomCalendarProps extends ReactCalendarProps {
  className?: string;
  showOutsideDays?: boolean;
  mode?: 'range' | 'single';
  onRangeSelect?: (range: { start: Date | null; end: Date | null }) => void;
}

export function Calendar({
  className,
  showOutsideDays = true,
  mode = 'single',
  onRangeSelect,
  ...props
}: CustomCalendarProps) {
  const [selectedRange, setSelectedRange] = React.useState<{
    start: Date | null;
    end: Date | null;
  }>({ start: null, end: null });

  const handleDateClick = (date: Date) => {
    if (mode === 'range') {
      if (!selectedRange.start || selectedRange.end) {
        setSelectedRange({ start: date, end: null });
      } else {
        const newRange = {
          start: selectedRange.start,
          end: date >= selectedRange.start ? date : selectedRange.start,
        };
        setSelectedRange(newRange);
        onRangeSelect?.(newRange);
      }
    } else {
      setSelectedRange({ start: date, end: null });
    }
  };

  return (
    <div className={cn('p-3', className)}>
      <CalendarBase
        {...props}
        prevLabel={<ChevronLeftIcon className="h-4 w-4" />}
        nextLabel={<ChevronRightIcon className="h-4 w-4" />}
        prev2Label={null} // Hide the double backward navigation
        next2Label={null} // Hide the double forward navigation
        tileClassName={({ date }) =>
          cn(
            'p-2 text-center rounded-md transition-colors',
            selectedRange.start &&
              selectedRange.end &&
              date >= selectedRange.start &&
              date <= selectedRange.end &&
              'bg-primary text-primary-foreground',
            selectedRange.start?.toDateString() === date.toDateString() &&
              'bg-accent text-accent-foreground font-bold',
            'hover:bg-muted hover:text-foreground'
          )
        }
        tileDisabled={({ date }) =>
          !showOutsideDays && date.getMonth() !== new Date().getMonth()
        }
        onClickDay={handleDateClick}
        className="rounded-lg border border-input bg-background shadow-md"
      />
      {mode === 'range' && selectedRange.start && (
        <div className="mt-4 text-sm">
          Selected range:{' '}
          <span className="font-semibold">
            {selectedRange.start.toDateString()}
          </span>{' '}
          to{' '}
          <span className="font-semibold">
            {selectedRange.end?.toDateString() || '...'}
          </span>
        </div>
      )}
    </div>
  );
}

Calendar.displayName = 'Calendar';