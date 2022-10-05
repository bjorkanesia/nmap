local datafiles = require "datafiles"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
http-dict enumerates dictionary attack on web servers with a purpose to identify 200, 401 code. 

Dictionary by DirSearch. 
See https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt
Store dictionary into nmap/nselib/data/
]]

author = {"P0lW4N", "9MM"}
categories = {"discovery", "intrusive", "vuln"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local limit = stdnse.get_script_args(SCRIPT_NAME .. '.limit')

  local ft = stdnse.get_script_args(SCRIPT_NAME .. '.ft')

 if(not nmap.registry.userdir) then
    init()
  end
  local dict = nmap.registry.userdir

  -- speedy exit if no dictionary
  if(#dict == 0) then
    return fail("Didn't find any dictionary (should be in nselib/data/dicc.txt)")
  end

  -- Identify servers that answer 200 to invalid HTTP requests and exit as these would invalidate the tests
  local status_404, result_404, known_404 = http.identify_404(host,port)
  if ( status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s:%s. All URIs return status 200.", host.ip, port.number)
    return nil
  end

print("\n\27[1;33m[ http dictionary attack ]\27[0m\n")
print("Dictionary Limit:",limit,"\nFile Type:",ft)
-- Queue up the checks
  local all = {}
  local i
  for i = 1, #dict, 1 do
    if(nmap.registry.args.limit and i > tonumber(nmap.registry.args.limit)) then
      stdnse.debug1("Reached the limit (%d), stopping", nmap.registry.args.limit)
      break;
    end
  
  --print(dict[i])
  -- local ft = stdnse.get_script_args(SCRIPT_NAME .. '.ft')
   if(dict[i]) then
     if(nmap.registry.args.ft == nil) then
	x = dict[i]                                           z = x:gsub("%%","")
        a = z:gsub("EXT", "512801")
     else
   x = dict[i]
   z = x:gsub("%%","")
  -- print(z)
   a = z:gsub("EXT", ft)

   --print(a)
   end
   dict[i] = a
  end
 -- print(dict[i])
  all = http.pipeline_add("/" .. dict[i], nil, all, 'GET')
  end

  local results = http.pipeline_go(host, port, all)
                                  
  -- Check for http.pipeline error
  if(results == nil) then
    stdnse.debug1("http.pipeline returned nil")
    return fail("http.pipeline returned nil")
  end

  local found = {}
  for i, data in pairs(results) do
    if(http.page_exists(data, result_404, known_404, "/" .. dict[i], true)) then
      stdnse.debug1("Found: %s", dict[i])
      table.insert(found, dict[i])
    end
  end

  if(#found > 0) then
 
 print("\n\27[1m[FOUND]\27[1;32m")
 print(table.concat(found,"\n" ),"\27[0m\27[0m" )
 print("\n")
 return found
 
  elseif(nmap.debugging() > 0) then
  return "Found Nothing"
  end
  return nil
end




function init()
  local dictionary = stdnse.get_script_args(SCRIPT_NAME .. '.users')
  local read, dict = datafiles.parse_file(dictionary or "nselib/data/dicc.txt", {})
  if not read then
    stdnse.debug1("%s", dict or "Unknown Error reading dictionary list.")
    nmap.registry.userdir = {}
    return nil
  end
  -- random dummy username to catch false positives (not necessary)
--if #usernames > 0 then table.insert(usernames, 1, randomstring()) end
  nmap.registry.userdir = dict
  stdnse.debug1("Testing %d dictionary.", #dict)
  return nil
end
