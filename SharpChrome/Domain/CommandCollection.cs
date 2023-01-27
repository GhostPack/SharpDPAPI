﻿using System;
using System.Collections.Generic;
using SharpChrome.Commands;

namespace SharpChrome.Domain
{
    public class CommandCollection
    {
        private readonly Dictionary<string, Func<ICommand>> _availableCommands = new Dictionary<string, Func<ICommand>>();

        // How To Add A New Command:
        //  1. Create your command class in the Commands Folder
        //      a. That class must have a CommandName static property that has the Command's name
        //              and must also Implement the ICommand interface
        //      b. Put the code that does the work into the Execute() method
        //  2. Add an entry to the _availableCommands dictionary in the Constructor below.

        public CommandCollection()
        {
            _availableCommands.Add(Backupkey.CommandName, () => new Backupkey());
            _availableCommands.Add(Logins.CommandName, () => new Logins());
            _availableCommands.Add(LoginsExport.CommandName, () => new LoginsExport());
            _availableCommands.Add(Cookies.CommandName, () => new Cookies());
            _availableCommands.Add(Statekeys.CommandName, () => new Statekeys());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound = false;
            else
            {
                // Create the command object 
                var command = _availableCommands[commandName].Invoke();

                // and execute it with the arguments from the command line
                command.Execute(arguments);

                commandWasFound = true;
            }

            return commandWasFound;
        }
    }
}