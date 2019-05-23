using System.Collections.Generic;

namespace SharpChrome.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}