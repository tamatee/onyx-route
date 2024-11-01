# timing_tool.py
import time
from termcolor import colored
from collections import defaultdict

class ProcessTimer:
    def __init__(self):
        self.timestamps = []
        self.process_times = defaultdict(list)
        self.start_times = {}
        self.total_start = None
        
    def start_process(self, process_name):
        """Start timing a specific process"""
        self.start_times[process_name] = time.time()
        self.timestamps.append({
            'time': time.time(),
            'action': f'Start {process_name}',
            'process': process_name,
            'type': 'start'
        })
        
        if self.total_start is None:
            self.total_start = time.time()
    
    def end_process(self, process_name):
        """End timing a specific process"""
        if process_name in self.start_times:
            end_time = time.time()
            duration = end_time - self.start_times[process_name]
            self.process_times[process_name].append(duration)
            
            self.timestamps.append({
                'time': end_time,
                'action': f'End {process_name}',
                'process': process_name,
                'type': 'end',
                'duration': duration
            })
            
            del self.start_times[process_name]
    
    def mark_timestamp(self, description):
        """Mark a specific timestamp without duration"""
        self.timestamps.append({
            'time': time.time(),
            'action': description,
            'type': 'mark'
        })
    
    def get_summary(self):
        """Get summary of all process times"""
        summary = []
        total_time = time.time() - self.total_start if self.total_start else 0
        
        summary.append(colored("\n=== Timing Summary ===", "cyan"))
        
        # Process-specific times
        for process, times in self.process_times.items():
            avg_time = sum(times) / len(times)
            min_time = min(times)
            max_time = max(times)
            total = sum(times)
            
            summary.append(colored(f"\n{process}:", "yellow"))
            summary.append(f"  Average time: {avg_time*1000:.2f} ms")
            summary.append(f"  Min time: {min_time*1000:.2f} ms")
            summary.append(f"  Max time: {max_time*1000:.2f} ms")
            summary.append(f"  Total time: {total*1000:.2f} ms")
            summary.append(f"  Call count: {len(times)}")
        
        # Timeline of events
        summary.append(colored("\n=== Event Timeline ===", "cyan"))
        start_time = self.timestamps[0]['time'] if self.timestamps else time.time()
        
        for event in self.timestamps:
            relative_time = (event['time'] - start_time) * 1000  # Convert to ms
            if event['type'] == 'mark':
                summary.append(f"{relative_time:8.2f} ms: {event['action']}")
            elif event['type'] == 'end':
                summary.append(
                    f"{relative_time:8.2f} ms: {event['action']} " +
                    colored(f"(took {event['duration']*1000:.2f} ms)", "green")
                )
            else:
                summary.append(f"{relative_time:8.2f} ms: {event['action']}")
        
        summary.append(colored(f"\nTotal execution time: {total_time*1000:.2f} ms", "cyan"))
        return "\n".join(summary)
    
    def reset(self):
        """Reset all timings"""
        self.timestamps.clear()
        self.process_times.clear()
        self.start_times.clear()
        self.total_start = None
