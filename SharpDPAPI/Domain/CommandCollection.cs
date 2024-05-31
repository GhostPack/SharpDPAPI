﻿using System;
using System.Collections.Generic;
using SharpDPAPI.Commands;

namespace SharpDPAPI.Domain
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
            _availableCommands.Add(Blob.CommandName, () => new Blob());
            _availableCommands.Add(Credentials.CommandName, () => new Credentials());
            _availableCommands.Add(Keepass.CommandName, () => new Keepass());
            _availableCommands.Add(Machinecredentials.CommandName, () => new Machinecredentials());
            _availableCommands.Add(Machinemasterkeys.CommandName, () => new Machinemasterkeys());
            _availableCommands.Add(Machinetriage.CommandName, () => new Machinetriage());
            _availableCommands.Add(Machinevaults.CommandName, () => new Machinevaults());
            _availableCommands.Add(Masterkeys.CommandName, () => new Masterkeys());
            _availableCommands.Add(PS.CommandName, () => new PS());
            _availableCommands.Add(RDG.CommandName, () => new RDG());
            _availableCommands.Add(UserTriage.CommandName, () => new UserTriage());
            _availableCommands.Add(Vaults.CommandName, () => new Vaults());
            _availableCommands.Add(Certificate.CommandName, () => new Certificate());
            _availableCommands.Add(Search.CommandName, () => new Search());
            _availableCommands.Add(SCCM.CommandName, () => new SCCM());
            _availableCommands.Add(Protect.CommandName, () => new Protect());
        }

        public bool ExecuteCommand(string commandName, Dictionary<string, string> arguments)
        {
            bool commandWasFound;

            if (string.IsNullOrEmpty(commandName) || _availableCommands.ContainsKey(commandName) == false)
                commandWasFound= false;
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