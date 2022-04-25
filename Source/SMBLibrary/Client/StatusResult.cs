namespace SMBLibrary.Client
{
    public class StatusResult<T>
    {
        public StatusResult(T result, NTStatus status)
        {
            Result = result;
            Status = status;
        }

        public T Result { get; }

        public NTStatus Status { get; }
    }

    public class StatusResult<T1, T2>
    {
        public StatusResult(T1 result1, T2 result2, NTStatus status)
        {
            Result1 = result1;
            Result2 = result2;
            Status = status;
        }

        public T1 Result1 { get; }
        public T2 Result2 { get; }

        public NTStatus Status { get; }
    }
}