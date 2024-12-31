"""
	A basic monitor that provides a more convenient use of the process Groups.
"""
import multiprocessing
import time

from shelljob import proc

"""
	Manages a Group by collecting output and displaying feedback. This is an abstract
	class which provides the basic mechanism.
"""
class Monitor(object):
	
	def __init__( self, max_simul = multiprocessing.cpu_count(), feedback_timeout = 5.0 ):
		"""
			@param max_simul: the maximum number of processes which can be running
				at the same time
			@param feedback_timeout: generate progress feedback at this interval
		"""
		self.group = proc.Group()
		self.max_simul = max_simul
		self.jobs = {}
		self.feedback_timeout = feedback_timeout
		self.last_feedback = time.time()
		self.job_count = 0
		
	def convert_cmds( self, in_cmds ):
		"""
			Converts a variable format input command list to a set of Jobs.
		"""
		out_cmds = []
		for cmd in in_cmds:
			if not isinstance(cmd,Job):
				cmd = Job(cmd)
				
			if cmd.id == None:
				cmd.id = self.job_count
				self.job_count += 1
				
			out_cmds.append( cmd )
		return out_cmds
		
	def run( self, cmds, shell = False ):
		"""
			Run a series of commands and wait for their completion.
			
			@param cmds: a list of cmds or Job's for Group.run. This will be run in parallel obeying the
				'max_simul' option provided to the constructor. Using Job's directly allows you to associate
				additional data for use with each job -- helpful for custom monitors.
		"""
		cmds = self.convert_cmds( cmds )
		
		while True:
			# ensure max_simul are running
			run_count = self._check_finished()
			if run_count < self.max_simul and len(cmds):
				# space to create a new job
				job = cmds[0]
				job.handle = self.group.run( job.cmd, shell = shell )
				job.status = Job.STATUS_RUNNING
				cmds = cmds[1:]
				
				self.jobs[job.handle] = job
				self.job_started(job)
				# this allows a quick spawing of max_simul on first call
				continue
			
			lines = self.group.readlines()
			for handle, line in lines:
				self.job_output( self.jobs[handle], line )
				
			self._check_feedback()
				
			if run_count == 0:
				break
		
		self.gen_feedback()
				
	def _check_finished(self):
		"""
			Process all finished items.
			
			@return: count of still running jobs
		"""
		codes = self.group.get_exit_codes()
		count_run = 0
		count_done = 0
		for handle, code in codes:
			# it must be done and no output left before we consider it done
			if code == None or not handle.group_output_done:
				count_run += 1
				continue
				
			job = self.jobs[handle]
			job.status = Job.STATUS_FINISHED
			job.exit_code = code
			count_done += 1
			self.job_finished( job )

		if count_done > 0:
			self.group.clear_finished()
			
		return count_run
		
	def _check_feedback(self):
		"""
			Call gen_feedback at regular interval.
		"""
		elapsed = time.time() - self.last_feedback
		if elapsed > self.feedback_timeout:
			self.gen_feedback()
			self.last_feedback = time.time()
		
	def job_finished(self, job):
		"""
			(Virtual) Called when a job has completed.
		"""
		pass
		
	def job_started(self, job):
		"""
			(Virtual) Called just after a job is started.
		"""
		pass
		
	def job_output(self, job, line):
		"""
			(Virtual) Called for each line of output from a job.
		"""
		pass
		
	def gen_feedback(self):
		"""
			(Virtual) Called whenever the Monitor things feedback should be generated (in addition to the other
			events). Generally this is called for each feedback_timeout period specified in the constructor.
		"""
		pass

	def get_jobs(self):
		"""
			Get the list of jobs.
		"""
		return self.jobs.values()
		
class Job:
	STATUS_NONE = 0
	STATUS_RUNNING = 1
	STATUS_FINISHED = 2
	
	"""
		Encapsulates information about a job.
	"""
	def __init__(self, cmd):
		# the Popen object, set by monitor when the job starts
		self.handle = None
		# An identifier, if set to None then monitor will assign one (incrementing)
		self.id = None
		# command executed by the job
		self.cmd = cmd
		# Current status of the job
		self.status = Job.STATUS_NONE
		# Value of the exit code from the process, or None if not yet finished
		self.exit_code = None
		# An identifying name
		self.name = None
		
	def get_ref_name(self):
		"""
			A reference name suitable for using in identifiers and files.
		"""
		if not self.name:
			return self.id
		
		# generate simple safe filename
		base = self.name.replace( '/', '_' ).replace( '\\', '_' ).replace( ' ', '_' )
		keep = ('_','.')
		return "".join( c for c in base if c.isalnum() or c in keep )

		
class FileMonitor(Monitor):
	"""
		A monitor which writes output to log files. Simple textual feedback will also be reported
		to the console.
		
		@param file_pattern: will be formatted with the job.id to produce filenames. These files
			are overwritten when a job starts and record the output of the job.
		@param meta: if True then meta information about the job will also be recorded to the
			logfile
		@param kwargs: the remaining arguments are passed to the Monitor constructor
	"""
	def __init__(self, file_pattern = '/tmp/job_{}.log', meta = True, **kwargs):
		super(FileMonitor,self).__init__( **kwargs )
		self.file_pattern = file_pattern
		self.meta = meta
		
	def get_log_name(self,job):
		"""
			(Virtual) get the log of the log file to use.
		"""
		return self.file_pattern.format( job.get_ref_name() )
		
	def job_finished(self, job):
		"""
			Called when a job has completed.
		"""
		if self.meta:
			job.log_file.write( "Exit Code: {}\n".format( job.exit_code ).encode() )
			
		job.log_file.close()
		
	def job_started(self, job):
		"""
			Called just after a job is started.
		"""
		job.log_name = self.get_log_name(job)
		job.log_file = open(job.log_name,'wb')
		job.got_output = False
		
		if self.meta:
			job.log_file.write( "Job #{}: {}\n".format( job.id, job.cmd ).encode() )
		
	def job_output(self, job, line):
		"""
			Called for each line of output from a job.
		"""
		job.log_file.write(line)
		job.got_output = True
		
	def gen_feedback(self):
		"""
			Called whenever the Monitor things feedback should be generated (in addition to the other
			events). Generally this is called for each feedback_timeout period specified in the constructor.
		"""
		good = 0
		bad = 0
		output = 0
		stall = 0
		for job in self.get_jobs():
			if job.exit_code != None:
				if job.exit_code == 0:
					good += 1
				else:
					bad += 1
			elif job.got_output:
				job.got_output = False
				output += 1
			else:
				stall += 1
	
		print( "Done: {}  Failed: {}  Reading: {}  Idle: {}".format( good, bad, output, stall ) )
		