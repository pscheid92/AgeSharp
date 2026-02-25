using Age.Cli;

return args.Length switch
{
    > 0 when args[0] == "keygen" => KeygenCommand.Run(args[1..]),
    > 0 when args[0] == "inspect" => InspectCommand.Run(args[1..]),
    _ => AgeCommand.Run(args)
};