# Redis를 활용하여 유니크값 관리하기

### 개요

플레이어가 방을 만들 때를 생각해보자. 필요한값은 RoomId, RoomTitle, HostUserId, Users[]… 등이 있을 것이다. 여기서 title이나 hostuserId등은 request값으로 받아서 넣을 수 있다. 하지만 RoomId는 어떻게 받을것인가 

다양한 방법이 있을 수 있다. 

### 웹서버에서 싱글톤으로 관리

가장 보편적이고 쉬운방법이다. 하지만 서버가 스케일아웃으로 구현이 된다면 유니크한 값을 보장받지 못하게 된다. 

### Mysql로 Auto Increasement를 사용하여 관리

Auto Increasement로 유니크한 값을 관리할 수 있지만 샤딩을 사용하게 되면 해당 부분이 깨지게 된다. 또한 Redis에 데이터를 저장할건데 굳이 Mysql까지 Cost를 낭비할 필요는 없다 

### Redis의 Lua Script활용하기

Redis의 특징 중 하나는 명령어 단위를 처리를 싱글 스레드로 처리한다는 것이다. 그렇기에 외부 다른 스레드가 동시에 접근해도  그 순간적으로는 하나만 처리하기에 동시성이 보장된다. 하지만 명령어 단위이기 때문에 A라는 명령어를 처리하고 B라는 명령어를 처리할 때 다른 스레드가 사이에 낄 수 있다는 것이다. 

그렇기에 Redis에서는 Lua Script 파일 하나를 하나의 명령어로 인식하여 명령어를 Atomic하게 처리하는 것이 존재한다. 

아래는 Redis의 Lua script를 사용하여 RoomId에 대해 유니크하게 값을 가지고온 다음 값을 1증가할것이다. ㅇ

### Redis Lua

```csharp
redis set UNIQUE_KEY 1

-- Lua Script With ASP.NET Core
async public Task<(ErrorCode, int)> LoadUniqueRoomId()
        {
            try
            {
                var script =
@"local roomId = tonumber(redis.call('get', KEYS[1])) 
redis.call('incr', KEYS[1])
return roomId
";
                var redis = new RedisLua(_redisConn, _dbConfig.Value.RedisUniqueRoomKey);
                var keys = new RedisKey[] { _dbConfig.Value.RedisUniqueRoomKey };
                var values = new RedisValue[] {  };
                var roomId = await redis.ScriptEvaluateAsync<int>(script, keys, values);
                return (ErrorCode.None, roomId.Value);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return (ErrorCode.CannotConnectServer, -1);
            }
        }
```

위 코드를 통해 roomId를 가지고오고 roomId의 값을 1증가한다. 위의 명령어는 Atomic하게 동작한다. 

아래 코드는 방의 인원수(HeadCount)가 인자로 주어진 값보다 작다면 Users에 userId를 추가하는 코드이다. 이 또한 Atomic하게 이루어져야 한다. 

⇒ 그렇지 않으면 HeadCount가 ARGV[1]보다 작다면 실행하고 값을 넣을 떄 다른 스레드가 다음 명령어를 처리하면 Users엔 3명이 들어가는 대참사가 벌어진다. 

```csharp
async public Task<ErrorCode> EnterRoom(int userId, int roomId)
        {
            try
            {
                var script =
@"
local rooms = redis.call('SMEMBERS', KEYS[1])
for _, member in ipairs(rooms) do 
    local obj = cjson.decode(member)
    if tonumber(obj.RoomId) == tonumber(ARGV[1]) then 
        if #obj.Users < obj.HeadCount then
            redis.call('SREM', KEYS[1], member)
            table.insert(obj.Users, tonumber(ARGV[2]))     
            redis.call('SADD', KEYS[1], cjson.encode(obj))
            return 0
        else
            return 1
        end
    end
end 
return 2
";
                var redis = new RedisLua(_redisConn, "ROOMS");
                var keys = new RedisKey[] { "ROOMS" };
                var values = new RedisValue[] { roomId, userId };
                var result = await redis.ScriptEvaluateAsync<int>(script, keys, values);

                if(result.Value != 0)
                {
                    if(result.Value == 1)
                    {
                        return ErrorCode.AlreadyFullRoom;
                    }
                    else if(result.Value == 2)
                    {
                        return ErrorCode.NoneExistRoom;
                    }
                }
                return ErrorCode.None;
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return ErrorCode.CannotConnectServer;
            }
        }
```