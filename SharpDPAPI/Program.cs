using SharpDPAPI.Domain;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace SharpDPAPI
{
    class Program
    {
        private static void FileExecute(string commandName, Dictionary<string, string> parsedArgs)
        {
            // execute w/ stdout/err redirected to a file

            string file = parsedArgs["/consoleoutfile"];

            TextWriter realStdOut = Console.Out;
            TextWriter realStdErr = Console.Error;

            using (StreamWriter writer = new StreamWriter(file, true))
            {
                writer.AutoFlush = true;
                Console.SetOut(writer);
                Console.SetError(writer);

                MainExecute(commandName, parsedArgs);

                Console.Out.Flush();
                Console.Error.Flush();
            }
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);
        }

        private static void MainExecute(string commandName, Dictionary<string, string> parsedArgs)
        {
            // main execution logic
            Stopwatch sw = new Stopwatch();
            sw.Start();

            Info.ShowLogo();

            try
            {
                var commandFound = new CommandCollection().ExecuteCommand(commandName, parsedArgs);

                // show the usage if no commands were found for the command name
                if (commandFound == false)
                    Info.ShowUsage();
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled SharpDPAPI exception:\r\n");
                Console.WriteLine(e);
            }

            sw.Stop();
            Console.WriteLine("\n\nSharpDPAPI completed in " + sw.Elapsed);
        }

        public static string MainString(string command)
        {
            // helper that executes an input string command and returns results as a string
            //  useful for PSRemoting execution

            string[] args = command.Split();

            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                Info.ShowLogo();
                Info.ShowUsage();
                return "Error parsing arguments: ${command}";
            }

            var commandName = args.Length != 0 ?  args[0].ToLower() : "";

            TextWriter realStdOut = Console.Out;
            TextWriter realStdErr = Console.Error;
            TextWriter stdOutWriter = new StringWriter();
            TextWriter stdErrWriter = new StringWriter();
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);

            MainExecute(commandName, parsed.Arguments);

            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);

            string output = "";
            output += stdOutWriter.ToString();
            output += stdErrWriter.ToString();

            return output;
        }

        static void Main(string[] args)
        {
            try
            {
                var parsed = ArgumentParser.Parse(args);
                if (parsed.ParsedOk == false)
                {
                    Info.ShowLogo();
                    Info.ShowUsage();
                    return;
                }

                var commandName = args.Length != 0 ? args[0].ToLower() : "";

                if (parsed.Arguments.ContainsKey("/consoleoutfile"))
                {
                    // redirect output to a file specified
                    FileExecute(commandName, parsed.Arguments);
                }
                else
                {
                    MainExecute(commandName, parsed.Arguments);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled SharpDPAPI exception:\r\n");
                Console.WriteLine(e);
            }
        }
    }
}
