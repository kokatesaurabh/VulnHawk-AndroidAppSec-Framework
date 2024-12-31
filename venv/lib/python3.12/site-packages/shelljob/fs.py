"""
	A collection of filesystem related commands.
"""
import os, re, tempfile

def find( path, 
	include_dirs = True, include_files = True,
	name_regex = None, not_name_regex = None,
	whole_name_regex = None, not_whole_name_regex = None,
	exclude_root = False, relative = False,
	limit_depth = None ):
	"""
		Creates an iterator of files matching a variety of conditions.
		
		@param path: which path to iterate
		@param include_dirs: include directories in output
		@param include_files: include files in output
		@param name_regex: optional regex string compared against basename of file
		@param not_name_regex: if specificed only produces names not matching this regex
		@param whole_name_regex: like name_regex but applies to whole path, not just basename
		@param not_whole_name_regex: like not_name_regex but applies to whole path
		@param exclude_root: do not include the intput 'path' itself in the output
		@param limit_depth: do not list items deeper than this level from root
		@param relative: filenames are relative to "path" as opposed to appended to path
		@return: a generator for the matched files
	"""
	def maybe_regex(arg):
		return re.compile(arg) if arg != None else None
	c_name_regex = maybe_regex(name_regex)
	c_not_name_regex = maybe_regex(not_name_regex)
	c_whole_name_regex = maybe_regex(whole_name_regex)
	c_not_whole_name_regex = maybe_regex(not_whole_name_regex)
	
	def check_name(name, whole_name):
		if c_name_regex != None and not c_name_regex.match( name ):
			return False
		if c_not_name_regex != None and c_not_name_regex.match( name ):
			return False
		if c_whole_name_regex != None and not c_whole_name_regex.match( whole_name ):
			return False
		if c_not_whole_name_regex != None and c_not_whole_name_regex.match( whole_name ):
			return False
		return True
		
	def result( whole, rel ):
		if relative:
			return rel
		else:
			return whole
			
	def filter_func():
		# A list of paths still to be processed (depth, whole_path, relative_path) 
		queue = [ ( 0, path, '' ) ]

		while len(queue) != 0:
			depth, root, rel_path = queue[0]
			queue = queue[1:]
			
			if root == path and exclude_root:
				pass
			elif include_dirs and check_name( os.path.basename(root), root ):
				yield result( root, rel_path )
				
			if limit_depth != None and depth > limit_depth:
				continue
				
			for item in os.listdir(root):
				whole = os.path.join( root, item )
				rel = os.path.join( rel_path, item )
					
				if os.path.isdir(whole):
					queue.append( ( depth + 1, whole, rel ) )
				elif include_files and check_name( item, whole ):
					yield result( whole, rel )
	
	return filter_func()

class NamedTempFile:
	"""
		Creates a temporary file for a 'with' block. The file is deleted when the block exits.
		This creates the file to ensure it exists/block a race, but does not write anything to
		it, nor does it keep it open. It is intended for times when you need a named file
		for subprocesses.
		
		Example::
		
			with fs.NamedTempFile() as nm:
				proc.call( "curl http://mortoray.com/ -o {}".format( nm ) )
				html = open(nm).read()
				print( len(html) )
		
	"""
	
	def __init__(self, suffix = None, prefix = None, dir = None ):
		"""
			@param suffix: optional suffix for generated filename (a dot '.' is not automatically added, 
				specifiy it if desired)
			@param prefix: optional prefix for generated filename
			@param dir: in which directory, if None then use a system default
		"""
		self.args = {
			'text': False,
		}
		if suffix != None:
			self.args['suffix'] = suffix
		if prefix != None:
			self.args['prefix'] = prefix
		if dir != None:
			self.args['dir'] = dir
		
	def __enter__(self):	
		(handle, name) = tempfile.mkstemp( **self.args )
		os.close(handle)
		self.name = name
		return name
		
	def __exit__(self, type, value, traceback):
		os.remove(self.name)
		